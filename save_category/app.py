import json
import pymysql
import logging
import re
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_secret():
    """
    Obtiene las credenciales de la base de datos desde AWS Secrets Manager.
    """
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
        return json.loads(get_secret_value_response['SecretString'])
    except NoCredentialsError as e:
        logger.error("No AWS credentials found")
        raise e
    except PartialCredentialsError as e:
        logger.error("Incomplete AWS credentials")
        raise e
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            logger.error("The requested secret was not found.")
        elif error_code == 'InvalidRequestException':
            logger.error("The request was invalid due to incorrect parameters.")
        elif error_code == 'AccessDeniedException':
            logger.error("Access denied to the requested secret.")
        else:
            logger.error(f"Unexpected error: {e}")
        raise e

# Obtener las credenciales desde Secrets Manager
secrets = get_secret()
rds_host = secrets["host"]
rds_user = secrets["username"]
rds_password = secrets["password"]
rds_db = secrets["dbname"]

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
        if re.search(r'[<>/`\\{}]', name):
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

        save_category(name)

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
        logger.error(f"Missing key: {e}")
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({
                "message": "MISSING_KEY",
                "error": str(e)
            }),
        }
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps({
                "message": "INTERNAL_SERVER_ERROR",
                "error": str(e)
            }),
        }

def is_name_duplicate(name):
    """
    Verifica si el nombre de la categoría ya existe en la base de datos.
    """
    try:
        connection = pymysql.connect(host=rds_host, user=rds_user, password=rds_password, db=rds_db)
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM categories WHERE name = %s", (name,))
            result = cursor.fetchone()
            return result[0] > 0
    except pymysql.MySQLError as e:
        logger.error("Database query error: %s", str(e))
        raise e
    finally:
        connection.close()

def save_category(name):
    """
    Guarda una nueva categoría en la base de datos.
    """
    try:
        connection = pymysql.connect(host=rds_host, user=rds_user, password=rds_password, db=rds_db)
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO categories (name, status) VALUES (%s, true)", (name,))
            connection.commit()
            logger.info("Database insert successful for name=%s", name)
    except pymysql.err.IntegrityError as e:
        logger.error("Integrity error: Duplicate entry or constraint violation")
        raise e
    except pymysql.err.OperationalError as e:
        logger.error("Operational error: Database is unavailable or access denied")
        raise e
    except pymysql.MySQLError as e:
        logger.error("Unexpected database error: %s", str(e))
        raise e
    finally:
        connection.close()
