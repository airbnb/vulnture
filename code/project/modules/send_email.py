"""Helper module that sends an email containing provided contents via SMTP
over SSL.
"""

from email.message import EmailMessage
import logging
import os
from smtplib import SMTP_SSL
import sys

import boto3
from botocore.exceptions import ClientError

# Initialize logger
LOGGER = logging.getLogger()
LOGGER.debug('send_email.py - {}'.format(__name__))


# Helper function to get email password from AWS Secrets Manager
def get_email_password():
    """Retrieves a password from the AWS Secrets Manager service.

    Returns
    -------
    str
        The password retrieved from AWS Secrets Manager
    """
    # This environment variable should contain the secret name for the
    # AWS Secrets Manager item containing the SMTP auth password - this is set
    # in variables.tf + vulnture.tf (Lambda function environment variable)
    env_var = 'EMAIL_PASSWORD_LOCATION'
    secret_name = os.getenv(env_var)
    if not secret_name:
        sys.exit('Environment variable {} not found!'.format(env_var))
    sm_client = boto3.client(service_name='secretsmanager')

    try:
        get_secret_value_response = sm_client.get_secret_value(
            SecretId=secret_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print('The requested secret ' + secret_name + ' was not found')
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print('The request was invalid due to:', e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print('The request had invalid params:', e)
    else:
        # Decrypted secret using the associated KMS CMK
        if 'SecretString' in get_secret_value_response:
            return get_secret_value_response['SecretString']
        else:
            return None


# Function to send email via SMTP (SSL/encrypted) containing message_contents
def send(smtp_server, sender, message_contents, recipient):
    """Sends email containing the passed in message contents to the recipient.

    Parameters
    ----------
    message_contents : str
        The contents of the email to be sent
    recipient : str
        The email address of the intended recipient
    """
    # Message details
    subject = 'vulnture - relevant vulnerabilities detected!'
    # Only do anything if vulnerabilities found (message_contents not empty)
    if message_contents:
        LOGGER.info('Sending email notification...')
        # SMTP sender password
        password = get_email_password()
        if not password:
            sys.exit('Failed to get email password to send notification!')

        # Create a text/plain message
        msg = EmailMessage()
        msg.set_content(message_contents)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient

        # Make SMTP connection, authenticate, send message, disconnect
        s = SMTP_SSL(smtp_server)
        s.login(sender, password)
        s.send_message(msg)
        s.quit()
        del password
