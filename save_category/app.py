import json
import pymysql
import logging
import re
import boto3
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "secretsForBalu"
    region_name = "us-east-2"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise Exception("Secrets Manager no pudo descifrar el secreto utilizando la clave KMS especificada.")
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise Exception("Ocurrió un error interno en Secrets Manager.")
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise Exception("Uno o más de los parámetros especificados no son válidos.")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise Exception("La solicitud no fue válida. Verifica los parámetros.")
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise Exception("El secreto solicitado no se encontró.")
        else:
            raise e

    secret = get_secret_value_response['SecretString']
    return json.loads(secret)

# Obtener las credenciales desde Secrets Manager
secrets = get_secret()
rds_host = secrets["host"]
rds_user = secrets["username"]
rds_password = secrets["password"]
rds_db = secrets["dbname"]

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, __):
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token"
    }
    try:
        claims = event['requestContext']['authorizer']['claims']
        role = claims['cognito:groups']

        if 'admin' not in role:
            return {
                "statusCode": 403,
                "headers": headers,
                "body": json.dumps({
                    "message": "FORBIDDEN"
                }),
            }

        body = json.loads(event.get('body', '{}'))
        name = body.get('name')

        if not name:
            logger.warning("Missing fields: name")
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({
                    "message": "MISSING_FIELDS"
                }),
            }

        # Verificar caracteres no permitidos
        if re.search(r'[<>/``\\{}]', name):
            logger.warning("Invalid characters in name")
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({
                    "message": "INVALID_CHARACTERS"
                }),
            }

        # Verificar nombre duplicado
        if is_name_duplicate(name):
            logger.warning("Duplicate category name: %s", name)
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({
                    "message": "DUPLICATE_NAME"
                }),
            }

        save_category(name, headers)
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps({
                "message": "CATEGORY_SAVED",
            }),
        }
    except json.JSONDecodeError:
        logger.error("Invalid JSON format")
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({
                "message": "INVALID_JSON_FORMAT"
            }),
        }
    except KeyError as e:
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({
                "message": "MISSING_KEY",
                "error": str(e)
            }),
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps({
                "message": "INTERNAL_SERVER_ERROR",
                "error": str(e)
            }),
        }

def is_name_duplicate(name):
    connection = pymysql.connect(host=rds_host, user=rds_user, password=rds_password, db=rds_db)
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM categories WHERE name = %s", (name,))
        result = cursor.fetchone()
        return result[0] > 0
    except Exception as e:
        logger.error("Database query error: %s", str(e))
        return False
    finally:
        connection.close()

def save_category(name, headers):
    print(f"name: {name}, headers: {headers}")
    connection = pymysql.connect(host=rds_host, user=rds_user, password=rds_password, db=rds_db)
    try:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO categories (name, status) VALUES (%s, true)", (name,))
        connection.commit()
        logger.info("Database create successfully for name=%s", name)
    except pymysql.err.IntegrityError as e:
        if e.args[0] == 1062:  # Código de error para duplicado
            logger.error("Error de integridad en la base de datos: %s", str(e))
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({
                    "message": "El nombre de la categoría ya existe. Por favor, elige otro."
                }),
            }
    except pymysql.Error as e:
        logger.error("Error en la base de datos: %s", str(e))
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps({
                "message": "Error al guardar la categoría. Por favor, inténtalo de nuevo más tarde."
            }),
        }
    finally:
        connection.close()
