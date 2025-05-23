import boto3
import logging
import os
import json
import string
import random

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secretsmanager = boto3.client('secretsmanager')

def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    metadata = secretsmanager.describe_secret(SecretId=arn)

    if not metadata['RotationEnabled']:
        raise ValueError("Secret rotation is not enabled")

    if token not in metadata['VersionIdsToStages'] or 'AWSCURRENT' in metadata['VersionIdsToStages'][token]:
        raise ValueError("Invalid or already-used version")

    if step == "createSecret":
        create_secret(arn, token)
    elif step == "setSecret":
        set_secret(arn, token)
    elif step == "testSecret":
        test_secret(arn, token)
    elif step == "finishSecret":
        finish_secret(arn, token)
    else:
        raise ValueError("Unknown step: " + step)

def create_secret(arn, token):
    try:
        # Essaie de récupérer la version avec le token
        secretsmanager.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: version already exists")
    except secretsmanager.exceptions.ResourceNotFoundException:
        # Génère un nouveau mot de passe
        password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=32))
        current = secretsmanager.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
        secret_dict = json.loads(current['SecretString'])
        secret_dict['password'] = password

        secretsmanager.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(secret_dict),
            VersionStages=['AWSPENDING']
        )
        logger.info("createSecret: new secret created")

def set_secret(arn, token):
    # Ici tu pourrais configurer l'utilisation du nouveau mot de passe dans ta base de données
    logger.info("setSecret: no external action implemented (mock)")

def test_secret(arn, token):
    # Tu pourrais tester ici la connexion à la DB avec le nouveau mot de passe
    logger.info("testSecret: test passed (mock)")

def finish_secret(arn, token):
    metadata = secretsmanager.describe_secret(SecretId=arn)
    current_version = None

    for version_id, stages in metadata['VersionIdsToStages'].items():
        if "AWSCURRENT" in stages:
            current_version = version_id
            break

    if current_version == token:
        logger.info("finishSecret: version already marked as AWSCURRENT")
        return

    secretsmanager.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version
    )
    logger.info("finishSecret: secret rotation complete")
