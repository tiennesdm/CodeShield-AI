"""
Custom AI-powered pattern scanner for CodeShield AI.

Pattern-based scanner that detects security vulnerabilities using regex patterns,
AST analysis, heuristics, and entropy-based secret detection. Runs on all languages
without external dependencies.

Includes 200+ secret patterns covering:
- Cloud providers: AWS, GCP, Azure, IBM Cloud
- APIs: OpenAI, Stripe, Twilio, SendGrid, Slack, Discord
- Databases: MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch
- CI/CD: GitHub, GitLab, Jenkins, CircleCI, Travis
- Social: Facebook, Twitter, Instagram, LinkedIn
- Messaging: Telegram, WhatsApp
- Payment: PayPal, Square, Braintree
- Crypto: Bitcoin, Ethereum
- Generic: JWT, base64 secrets, .env files
"""

import ast
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Tuple

from models.vulnerability import Vulnerability
from utils.constants import CWE_MAPPING, SEVERITY_LEVELS
from utils.helpers import count_lines, read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)


def shannon_entropy(string: str) -> float:
    """Calculate Shannon entropy of a string. Higher entropy (>4.0) suggests randomness typical of secrets."""
    if not string:
        return 0.0
    entropy = 0.0
    length = len(string)
    for count in (string.count(c) for c in set(string)):
        if count > 0:
            freq = count / length
            entropy -= freq * math.log2(freq)
    return entropy


def is_high_entropy(string: str, threshold: float = 4.0) -> bool:
    """Check if a string has high entropy (likely a secret)."""
    if len(string) < 20:
        return False
    if string in ("true", "false", "null", "undefined", "None", "True", "False"):
        return False
    # Reject strings that are a single repeated character (e.g. 'aaaa...').
    if re.fullmatch(r'(.)\\1+', string):
        return False
    if re.match(r'^(test|example|sample|dummy|placeholder)', string, re.I):
        return False
    return shannon_entropy(string) >= threshold


# AWS Patterns (25)
AWS_PATTERNS = [
    (r"(AKIA[0-9A-Z]{16})", "AWS Access Key ID", "CWE-798", "CRITICAL"),
    (r"(ASIA[0-9A-Z]{16})", "AWS Temporary Access Key", "CWE-798", "CRITICAL"),
    (r"(?i)(aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"])", "AWS Secret Access Key", "CWE-798", "CRITICAL"),
    (r"(?i)(aws[_-]?session[_-]?token\s*[:=]\s*['\"][A-Za-z0-9/+=]{16,}['\"])", "AWS Session Token", "CWE-798", "CRITICAL"),
    (r"(A3T[A-Z0-9]{17}A)", "AWS Root Access Key", "CWE-798", "CRITICAL"),
    (r"(?i)(aws[_-]?account[_-]?id\s*[:=]\s*['\"]?\d{12}['\"]?)", "AWS Account ID Exposed", "CWE-200", "MEDIUM"),
    (r"(?i)(x[_-]?amz[_-]?security[_-]?token\s*[:=]\s*['\"][A-Za-z0-9/+=]+['\"])", "AWS Security Token", "CWE-798", "CRITICAL"),
    (r"(?i)(aws[_-]?mfa[_-]?serial\s*[:=]\s*['\"]arn:aws:iam::\d{12}:mfa/[^'\"]+['\"])", "AWS MFA ARN", "CWE-200", "LOW"),
    (r"(?i)(arn:aws:iam::\d{12}:user/[\w+=,.@-]+)", "AWS IAM User ARN", "CWE-200", "LOW"),
    (r"(?i)(arn:aws:s3:::[a-z0-9._-]+)", "AWS S3 Bucket ARN", "CWE-200", "MEDIUM"),
    (r"(?i)(aws[_-]?s3[_-]?bucket[_-]?name\s*[:=]\s*['\"][a-z0-9._-]+['\"])", "AWS S3 Bucket Name", "CWE-200", "MEDIUM"),
    (r"(?i)(aws[_-]?rds[_-]?password\s*[:=]\s*['\"][^'\"]{8,}['\"])", "AWS RDS Password", "CWE-798", "CRITICAL"),
    (r"(?i)(aws[_-]?rds[_-]?endpoint\s*[:=]\s*['\"][^'\"]+['\"])", "AWS RDS Endpoint", "CWE-200", "LOW"),
    (r"(?i)(aws[_-]?elasticache[_-]?endpoint\s*[:=]\s*['\"][^'\"]+['\"])", "AWS ElastiCache Endpoint", "CWE-200", "LOW"),
    (r"(?i)(aws[_-]?sns[_-]?topic[_-]?arn\s*[:=]\s*['\"]arn:aws:sns:[^'\"]+['\"])", "AWS SNS Topic ARN", "CWE-200", "LOW"),
    (r"(?i)(aws[_-]?sqs[_-]?queue[_-]?url\s*[:=]\s*['\"]https://sqs\.[^'\"]+['\"])", "AWS SQS Queue URL", "CWE-200", "LOW"),
    (r"(?i)(aws[_-]?lambda[_-]?function[_-]?arn\s*[:=]\s*['\"]arn:aws:lambda:[^'\"]+['\"])", "AWS Lambda ARN", "CWE-200", "LOW"),
    (r"(?i)(aws[_-]?api[_-]?gateway[_-]?endpoint\s*[:=]\s*['\"]https://[a-z0-9]+\.execute-api\.[^'\"]+['\"])", "AWS API Gateway Endpoint", "CWE-200", "MEDIUM"),
    (r"(?i)(aws[_-]?cognito[_-]?pool[_-]?id\s*[:=]\s*['\"][a-z0-9_-]+/[a-z0-9_-]+['\"])", "AWS Cognito Pool ID", "CWE-200", "MEDIUM"),
    (r"(?i)(aws[_-]?cognito[_-]?app[_-]?client[_-]?secret\s*[:=]\s*['\"][a-z0-9]{26,}['\"])", "AWS Cognito App Client Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(aws[_-]?kms[_-]?key[_-]?id\s*[:=]\s*['\"][a-f0-9-]{36}['\"])", "AWS KMS Key ID", "CWE-200", "MEDIUM"),
    (r"(?i)(aws[_-]?dynamodb[_-]?table[_-]?name\s*[:=]\s*['\"'][a-zA-Z0-9._-]+['\"'])", "AWS DynamoDB Table Name", "CWE-200", "LOW"),
    (r"(?i)(ecr[_-]?repository[_-]?uri\s*[:=]\s*['\"']\d+\.dkr\.ecr\.[^'\"]+['\"'])", "AWS ECR Repository URI", "CWE-200", "LOW"),
    (r"(?i)(aws[_-]?cognito[_-]?app[_-]?client[_-]?id\s*[:=]\s*['\"'][a-z0-9]+['\"'])", "AWS Cognito App Client ID", "CWE-200", "MEDIUM"),
    (r"(?i)(aws[_-]?secrets[_-]?manager[_-]?arn\s*[:=]\s*['\"']arn:aws:secretsmanager:[^'\"]+['\"'])", "AWS Secrets Manager ARN", "CWE-200", "LOW"),
]

# GCP Patterns (18)
GCP_PATTERNS = [
    (r"(?i)(AIza[0-9A-Za-z_-]{33,})", "Google API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(gcp[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9_-]{39}['\"'])", "GCP API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(google[_-]?application[_-]?credentials\s*[:=]\s*['\"'][^'\"]*\.json['\"'])", "Google Application Credentials Path", "CWE-798", "HIGH"),
    (r"(?i)(gcp[_-]?service[_-]?account[_-]?key\s*[:=]\s*['\"']\{[^}]*type[^}]*service_account[^}]*\}['\"'])", "GCP Service Account Key JSON", "CWE-798", "CRITICAL"),
    (r"(?i)(gcp[_-]?oauth[_-]?client[_-]?id\s*[:=]\s*['\"']\d+-[a-z0-9]+\.apps\.googleusercontent\.com['\"'])", "GCP OAuth Client ID", "CWE-200", "MEDIUM"),
    (r"(?i)(gcp[_-]?oauth[_-]?client[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9_-]{24}['\"'])", "GCP OAuth Client Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(gcp[_-]?project[_-]?id\s*[:=]\s*['\"'][a-z][a-z0-9-]{4,28}[a-z0-9]['\"'])", "GCP Project ID", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?storage[_-]?bucket[_-]?name\s*[:=]\s*['\"'][a-z][a-z0-9._-]{2,61}[a-z0-9]['\"'])", "GCP Storage Bucket Name", "CWE-200", "MEDIUM"),
    (r"(?i)(firebase[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9_-]{39}['\"'])", "Firebase API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(firebase[_-]?project[_-]?id\s*[:=]\s*['\"'][a-z][a-z0-9-]+['\"'])", "Firebase Project ID", "CWE-200", "LOW"),
    (r"(?i)(firebase[_-]?auth[_-]?domain\s*[:=]\s*['\"'][a-z0-9-]+\.firebaseapp\.com['\"'])", "Firebase Auth Domain", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?service[_-]?account[_-]?email\s*[:=]\s*['\"'][a-z0-9._-]+@[a-z0-9._-]+\.iam\.gserviceaccount\.com['\"'])", "GCP Service Account Email", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?compute[_-]?instance[_-]?name\s*[:=]\s*['\"'][a-z][a-z0-9-]+['\"'])", "GCP Compute Instance Name", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?cloud[_-]?sql[_-]?instance[_-]?name\s*[:=]\s*['\"'][a-z][a-z0-9-]+['\"'])", "GCP Cloud SQL Instance Name", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?bigquery[_-]?dataset[_-]?id\s*[:=]\s*['\"'][a-zA-Z0-9_]+['\"'])", "GCP BigQuery Dataset ID", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?pubsub[_-]?topic[_-]?name\s*[:=]\s*['\"'][a-zA-Z0-9._~-]+['\"'])", "GCP Pub/Sub Topic Name", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?function[_-]?name\s*[:=]\s*['\"'][a-z](?:[-a-z0-9]{0,61}[a-z0-9])?['\"'])", "GCP Cloud Function Name", "CWE-200", "LOW"),
    (r"(?i)(gcp[_-]?cloud[_-]?run[_-]?service[_-]?name\s*[:=]\s*['\"'][a-z](?:[-a-z0-9]{0,61}[a-z0-9])?['\"'])", "GCP Cloud Run Service Name", "CWE-200", "LOW"),
]

# Azure Patterns (18)
AZURE_PATTERNS = [
    (r"(?i)(azure[_-]?subscription[_-]?id\s*[:=]\s*['\"'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"'])", "Azure Subscription ID", "CWE-200", "MEDIUM"),
    (r"(?i)(azure[_-]?tenant[_-]?id\s*[:=]\s*['\"'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"'])", "Azure Tenant ID", "CWE-200", "MEDIUM"),
    (r"(?i)(azure[_-]?client[_-]?id\s*[:=]\s*['\"'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"'])", "Azure Client ID", "CWE-200", "MEDIUM"),
    (r"(?i)(azure[_-]?client[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9~._-]{34,44}['\"'])", "Azure Client Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?storage[_-]?account[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9+/=]{88}['\"'])", "Azure Storage Account Key", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?storage[_-]?connection[_-]?string\s*[:=]\s*['\"']DefaultEndpointsProtocol=https;AccountName=[^'\"]+;AccountKey=[A-Za-z0-9+/=]+;EndpointSuffix=[^'\"]+['\"'])", "Azure Storage Connection String", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?cosmos[_-]?db[_-]?primary[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9+/=]{83}['\"'])", "Azure Cosmos DB Primary Key", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?cosmos[_-]?db[_-]?endpoint\s*[:=]\s*['\"']https://[a-z0-9-]+\.documents\.azure\.com:[0-9]+/['\"'])", "Azure Cosmos DB Endpoint", "CWE-200", "LOW"),
    (r"(?i)(azure[_-]?devops[_-]?pat\s*[:=]\s*['\"'][a-z0-9]{52}['\"'])", "Azure DevOps PAT", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?sas[_-]?token\s*[:=]\s*['\"']?sv=[0-9]+&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=[^&]+&st=[^&]+&spr=[a-z]+&sig=[A-Za-z0-9%]+['\"']?)", "Azure SAS Token", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?resource[_-]?group[_-]?name\s*[:=]\s*['\"'][a-zA-Z0-9._-]+['\"'])", "Azure Resource Group Name", "CWE-200", "LOW"),
    (r"(?i)(azure[_-]?key[_-]?vault[_-]?name\s*[:=]\s*['\"'][a-zA-Z0-9-]+['\"'])", "Azure Key Vault Name", "CWE-200", "MEDIUM"),
    (r"(?i)(azure[_-]?key[_-]?vault[_-]?secret[_-]?name\s*[:=]\s*['\"'][a-zA-Z0-9-]+['\"'])", "Azure Key Vault Secret Name", "CWE-200", "MEDIUM"),
    (r"(?i)(azure[_-]?sql[_-]?server[_-]?name\s*[:=]\s*['\"'][a-z0-9-]+\.database\.windows\.net['\"'])", "Azure SQL Server Name", "CWE-200", "LOW"),
    (r"(?i)(azure[_-]?service[_-]?bus[_-]?connection[_-]?string\s*[:=]\s*['\"']Endpoint=sb://[^'\"]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/=]+['\"'])", "Azure Service Bus Connection String", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?event[_-]?hub[_-]?connection[_-]?string\s*[:=]\s*['\"']Endpoint=sb://[^'\"]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/=]+['\"'])", "Azure Event Hub Connection String", "CWE-798", "CRITICAL"),
    (r"(?i)(azure[_-]?app[_-]?insights[_-]?instrumentation[_-]?key\s*[:=]\s*['\"'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"'])", "Azure App Insights Key", "CWE-200", "LOW"),
    (r"(?i)(azure[_-]?function[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9-_]{40,128}['\"'])", "Azure Function Key", "CWE-798", "HIGH"),
]

# IBM Cloud Patterns (7)
IBM_CLOUD_PATTERNS = [
    (r"(?i)(ibm[_-]?cloud[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9_-]{44}['\"'])", "IBM Cloud API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(ibm[_-]?cloud[_-]?iam[_-]?token\s*[:=]\s*['\"']Bearer [A-Za-z0-9_.-]+['\"'])", "IBM Cloud IAM Token", "CWE-798", "CRITICAL"),
    (r"(?i)(ibm[_-]?cloud[_-]?resource[_-]?group[_-]?id\s*[:=]\s*['\"'][0-9a-f]{32}['\"'])", "IBM Cloud Resource Group ID", "CWE-200", "LOW"),
    (r"(?i)(ibm[_-]?cloud[_-]?service[_-]?instance[_-]?id\s*[:=]\s*['\"'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"'])", "IBM Cloud Service Instance ID", "CWE-200", "LOW"),
    (r"(?i)(ibm[_-]?cloud[_-]?cos[_-]?hmac[_-]?access[_-]?key[_-]?id\s*[:=]\s*['\"'][a-f0-9]{32}['\"'])", "IBM COS HMAC Access Key", "CWE-798", "CRITICAL"),
    (r"(?i)(ibm[_-]?cloud[_-]?cos[_-]?hmac[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"'][a-f0-9]{64}['\"'])", "IBM COS HMAC Secret Key", "CWE-798", "CRITICAL"),
    (r"(?i)(ibm[_-]?cloud[_-]?crn\s*[:=]\s*['\"']crn:v1:bluemix:public:[^'\"]+['\"'])", "IBM Cloud CRN", "CWE-200", "LOW"),
]

# API Key Patterns (30+)
API_KEY_PATTERNS = [
    (r"(sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,})", "OpenAI API Key", "CWE-798", "CRITICAL"),
    (r"(sk-proj-[a-zA-Z0-9_-]{20,})", "OpenAI Project API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(openai[_-]?api[_-]?key\s*[:=]\s*['\"']sk-[^'\"]+['\"'])", "OpenAI API Key Assignment", "CWE-798", "CRITICAL"),
    (r"(?i)(openai[_-]?organization[_-]?id\s*[:=]\s*['\"']org-[a-zA-Z0-9]+['\"'])", "OpenAI Organization ID", "CWE-200", "LOW"),
    (r"(sk_live_[0-9a-zA-Z]{24,})", "Stripe Live Secret Key", "CWE-798", "CRITICAL"),
    (r"(sk_test_[0-9a-zA-Z]{24,})", "Stripe Test Secret Key", "CWE-798", "HIGH"),
    (r"(rk_live_[0-9a-zA-Z]{24,})", "Stripe Restricted Key (Live)", "CWE-798", "CRITICAL"),
    (r"(?i)(stripe[_-]?webhook[_-]?secret\s*[:=]\s*['\"']whsec_[a-zA-Z0-9]+['\"'])", "Stripe Webhook Secret", "CWE-798", "CRITICAL"),
    (r"(AC[0-9a-f]{32})", "Twilio Account SID", "CWE-200", "HIGH"),
    (r"(SK[0-9a-f]{32})", "Twilio API Key SID", "CWE-798", "CRITICAL"),
    (r"(?i)(twilio[_-]?auth[_-]?token\s*[:=]\s*['\"'][0-9a-f]{32}['\"'])", "Twilio Auth Token", "CWE-798", "CRITICAL"),
    (r"(?i)(sendgrid[_-]?api[_-]?key\s*[:=]\s*['\"']SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['\"'])", "SendGrid API Key", "CWE-798", "CRITICAL"),
    (r"(xox[baprs]-[0-9a-zA-Z]{10,48})", "Slack Token", "CWE-798", "CRITICAL"),
    (r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})", "Slack Bot Token", "CWE-798", "CRITICAL"),
    (r"(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})", "Slack User Token", "CWE-798", "CRITICAL"),
    (r"(xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})", "Slack App Token", "CWE-798", "CRITICAL"),
    (r"(xoxe-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})", "Slack OAuth Token", "CWE-798", "CRITICAL"),
    (r"(?i)(slack[_-]?webhook[_-]?url\s*[:=]\s*['\"']https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+['\"'])", "Slack Webhook URL", "CWE-798", "HIGH"),
    (r"(?i)(slack[_-]?signing[_-]?secret\s*[:=]\s*['\"'][0-9a-f]{32}['\"'])", "Slack Signing Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(slack[_-]?client[_-]?secret\s*[:=]\s*['\"'][0-9a-f]{32}['\"'])", "Slack Client Secret", "CWE-798", "CRITICAL"),
    (r"([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})", "Discord Bot Token", "CWE-798", "CRITICAL"),
    (r"(mfa\.[A-Za-z\d_-]{20,})", "Discord MFA Token", "CWE-798", "CRITICAL"),
    (r"(?i)(discord[_-]?webhook[_-]?url\s*[:=]\s*['\"']https://(discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+['\"'])", "Discord Webhook URL", "CWE-798", "HIGH"),
    (r"(?i)(discord[_-]?client[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9_-]{32}['\"'])", "Discord Client Secret", "CWE-798", "CRITICAL"),
    (r"(shpss_[a-fA-F0-9]{32})", "Shopify Private App Secret", "CWE-798", "CRITICAL"),
    (r"(shpat_[a-fA-F0-9]{32})", "Shopify Admin API Token", "CWE-798", "CRITICAL"),
    (r"(?i)(heroku[_-]?api[_-]?key\s*[:=]\s*['\"'][0-9a-f]{32}['\"'])", "Heroku API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(mailgun[_-]?api[_-]?key\s*[:=]\s*['\"']key-[0-9a-f]{32}['\"'])", "Mailgun API Key", "CWE-798", "CRITICAL"),
    (r"([0-9a-f]{32}-us[0-9]{1,2})", "Mailchimp API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(datadog[_-]?api[_-]?key\s*[:=]\s*['\"'][0-9a-f]{32}['\"'])", "Datadog API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(pagerduty[_-]?api[_-]?token\s*[:=]\s*['\"'][a-zA-Z0-9+]{20}['\"'])", "PagerDuty API Token", "CWE-798", "CRITICAL"),
    (r"(?i)(launchdarkly[_-]?sdk[_-]?key\s*[:=]\s*['\"'][a-f0-9-]{36}['\"'])", "LaunchDarkly SDK Key", "CWE-798", "CRITICAL"),
    (r"(?i)(algolia[_-]?api[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9]{32}['\"'])", "Algolia API Key", "CWE-798", "CRITICAL"),
]

# Database Patterns (25+)
DATABASE_PATTERNS = [
    (r"(mongodb(\+srv)?://[^:]+:[^@]+@[^/]+)", "MongoDB Connection String with Password", "CWE-798", "CRITICAL"),
    (r"(postgres(ql)?://[^:]+:[^@]+@[^/]+)", "PostgreSQL Connection String with Password", "CWE-798", "CRITICAL"),
    (r"(mysql://[^:]+:[^@]+@[^/]+)", "MySQL Connection String with Password", "CWE-798", "CRITICAL"),
    (r"(mariadb://[^:]+:[^@]+@[^/]+)", "MariaDB Connection String with Password", "CWE-798", "CRITICAL"),
    (r"(redis://:[^@]+@[^/]+)", "Redis Connection with Password", "CWE-798", "CRITICAL"),
    (r"(rediss://:[^@]+@[^/]+)", "Redis TLS Connection with Password", "CWE-798", "CRITICAL"),
    (r"(elasticsearch://[^:]+:[^@]+@[^/]+)", "Elasticsearch Connection with Password", "CWE-798", "CRITICAL"),
    (r"(http://elastic:[^@]+@[^/]+:9200)", "Elasticsearch Default User Connection", "CWE-798", "CRITICAL"),
    (r"(cassandra://[^:]+:[^@]+@[^/]+)", "Cassandra Connection with Password", "CWE-798", "CRITICAL"),
    (r"(couchdb://[^:]+:[^@]+@[^/]+)", "CouchDB Connection with Password", "CWE-798", "CRITICAL"),
    (r"(neo4j://[^:]+:[^@]+@[^/]+)", "Neo4j Connection with Password", "CWE-798", "CRITICAL"),
    (r"(bolt://[^:]+:[^@]+@[^/]+)", "Neo4j Bolt Connection with Password", "CWE-798", "CRITICAL"),
    (r"(influxdb://[^:]+:[^@]+@[^/]+)", "InfluxDB Connection with Password", "CWE-798", "CRITICAL"),
    (r"(cockroachdb://[^:]+:[^@]+@[^/]+)", "CockroachDB Connection with Password", "CWE-798", "CRITICAL"),
    (r"(sqlalchemy://[^:]+:[^@]+@[^/]+)", "SQLAlchemy Connection with Password", "CWE-798", "CRITICAL"),
    (r"(jdbc:[^:]+://[^:]+:[^@]+@[^/]+)", "JDBC Connection String with Password", "CWE-798", "CRITICAL"),
    (r"(?i)(database[_-]?url\s*[:=]\s*['\"'][^'\"]+://[^:]+:[^@]+@[^'\"]+['\"'])", "Database URL with Embedded Credentials", "CWE-798", "CRITICAL"),
    (r"(?i)(db[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded Database Password", "CWE-798", "CRITICAL"),
    (r"(?i)(db[_-]?host\s*[:=]\s*['\"'][^'\"]+['\"'])", "Database Host Exposed", "CWE-200", "LOW"),
    (r"(?i)(db[_-]?name\s*[:=]\s*['\"'][^'\"]+['\"'])", "Database Name Exposed", "CWE-200", "LOW"),
    (r"(?i)(db[_-]?user\s*[:=]\s*['\"'][^'\"]+['\"'])", "Database Username Exposed", "CWE-200", "MEDIUM"),
    (r"(?i)(redis[_-]?url\s*[:=]\s*['\"']redis://:[^@]+@[^'\"]+['\"'])", "Redis URL with Password", "CWE-798", "CRITICAL"),
    (r"(?i)(mongo[_-]?uri\s*[:=]\s*['\"']mongodb(\+srv)?://[^:]+:[^@]+@[^'\"]+['\"'])", "MongoDB URI with Password", "CWE-798", "CRITICAL"),
    (r"(?i)(postgres[_-]?url\s*[:=]\s*['\"']postgres(ql)?://[^:]+:[^@]+@[^'\"]+['\"'])", "PostgreSQL URL with Password", "CWE-798", "CRITICAL"),
]

# CI/CD Patterns (30+)
CICD_PATTERNS = [
    (r"(gh[pousr]_[A-Za-z0-9_]{36,})", "GitHub Personal Access Token", "CWE-798", "CRITICAL"),
    (r"(ghs_[A-Za-z0-9]{36})", "GitHub Server-to-Server Token", "CWE-798", "CRITICAL"),
    (r"(ghu_[A-Za-z0-9]{36})", "GitHub User Access Token", "CWE-798", "CRITICAL"),
    (r"(gho_[A-Za-z0-9]{36})", "GitHub OAuth Access Token", "CWE-798", "CRITICAL"),
    (r"(ghp_[A-Za-z0-9]{36})", "GitHub Personal Access Token (Classic)", "CWE-798", "CRITICAL"),
    (r"(?i)(github[_-]?webhook[_-]?secret\s*[:=]\s*['\"'][a-f0-9]{40}['\"'])", "GitHub Webhook Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(github[_-]?client[_-]?secret\s*[:=]\s*['\"'][a-f0-9]{40}['\"'])", "GitHub OAuth App Client Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(github[_-]?app[_-]?private[_-]?key\s*[:=]\s*['\"']-----BEGIN RSA PRIVATE KEY-----['\"'])", "GitHub App Private Key", "CWE-798", "CRITICAL"),
    (r"(?i)(github[_-]?app[_-]?id\s*[:=]\s*['\"']?\d+['\"']?)", "GitHub App ID", "CWE-200", "LOW"),
    (r"(?i)(github[_-]?app[_-]?installation[_-]?id\s*[:=]\s*['\"']?\d+['\"']?)", "GitHub App Installation ID", "CWE-200", "LOW"),
    (r"(glpat-[A-Za-z0-9_\-]{20})", "GitLab Personal Access Token", "CWE-798", "CRITICAL"),
    (r"(?i)(gitlab[_-]?private[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{20}['\"'])", "GitLab Private Token", "CWE-798", "CRITICAL"),
    (r"(?i)(gitlab[_-]?runner[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{20}['\"'])", "GitLab Runner Registration Token", "CWE-798", "CRITICAL"),
    (r"(?i)(gitlab[_-]?ci[_-]?job[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{20}['\"'])", "GitLab CI Job Token", "CWE-798", "HIGH"),
    (r"(?i)(jenkins[_-]?api[_-]?token\s*[:=]\s*['\"'][0-9a-f]{32}['\"'])", "Jenkins API Token", "CWE-798", "CRITICAL"),
    (r"(?i)(jenkins[_-]?user[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Jenkins User Password", "CWE-798", "CRITICAL"),
    (r"(?i)(circleci[_-]?api[_-]?token\s*[:=]\s*['\"'][0-9a-f]{40}['\"'])", "CircleCI API Token", "CWE-798", "CRITICAL"),
    (r"(?i)(travis[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{22}['\"'])", "Travis CI Token", "CWE-798", "CRITICAL"),
    (r"(?i)(bitbucket[_-]?app[_-]?password\s*[:=]\s*['\"'][A-Za-z0-9@_-]{24}['\"'])", "Bitbucket App Password", "CWE-798", "CRITICAL"),
    (r"(?i)(docker[_-]?hub[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Docker Hub Password", "CWE-798", "CRITICAL"),
    (r"(?i)(docker[_-]?hub[_-]?token\s*[:=]\s*['\"'][a-f0-9-]{36}['\"'])", "Docker Hub Access Token", "CWE-798", "CRITICAL"),
    (r"(?i)(docker[_-]?registry[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Docker Registry Password", "CWE-798", "CRITICAL"),
    (r"(?i)(k8s[_-]?token\s*[:=]\s*['\"']eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*['\"'])", "Kubernetes Service Account Token", "CWE-798", "CRITICAL"),
    (r"(?i)(terraform[_-]?cloud[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{14}\.atlasv1\.[A-Za-z0-9_-]{60,70}['\"'])", "Terraform Cloud API Token", "CWE-798", "CRITICAL"),
    (r"(?i)(netlify[_-]?auth[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{43,}['\"'])", "Netlify Auth Token", "CWE-798", "CRITICAL"),
    (r"(?i)(vercel[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{24}['\"'])", "Vercel Token", "CWE-798", "CRITICAL"),
    (r"(?i)(heroku[_-]?oauth[_-]?token\s*[:=]\s*['\"'][a-f0-9]{40}['\"'])", "Heroku OAuth Token", "CWE-798", "CRITICAL"),
    (r"(?i)(pusher[_-]?app[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{32}['\"'])", "Pusher App Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(npm[_-]?token\s*[:=]\s*['\"']npm_[a-zA-Z0-9]{36}['\"'])", "npm Token", "CWE-798", "CRITICAL"),
    (r"(?i)(pypi[_-]?api[_-]?token\s*[:=]\s*['\"']pypi-[A-Za-z0-9_\-]{30,}['\"'])", "PyPI API Token", "CWE-798", "CRITICAL"),
]

# Social Media Patterns (15+)
SOCIAL_PATTERNS = [
    (r"(?i)(facebook[_-]?app[_-]?secret\s*[:=]\s*['\"'][a-f0-9]{32}['\"'])", "Facebook App Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(facebook[_-]?access[_-]?token\s*[:=]\s*['\"']EAA[A-Za-z0-9]+['\"'])", "Facebook Access Token", "CWE-798", "CRITICAL"),
    (r"(?i)(facebook[_-]?app[_-]?id\s*[:=]\s*['\"']?\d{15,16}['\"']?)", "Facebook App ID", "CWE-200", "LOW"),
    (r"(?i)(twitter[_-]?api[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{43,50}['\"'])", "Twitter API Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(twitter[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{25}['\"'])", "Twitter API Key", "CWE-798", "HIGH"),
    (r"(?i)(twitter[_-]?bearer[_-]?token\s*[:=]\s*['\"']AAAA[a-zA-Z0-9%]{80,}['\"'])", "Twitter Bearer Token", "CWE-798", "CRITICAL"),
    (r"(?i)(twitter[_-]?access[_-]?token[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{43,45}['\"'])", "Twitter Access Token Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(twitter[_-]?access[_-]?token\s*[:=]\s*['\"']\d+-[A-Za-z0-9]{40}['\"'])", "Twitter Access Token", "CWE-798", "HIGH"),
    (r"(?i)(twitter[_-]?consumer[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{43,50}['\"'])", "Twitter Consumer Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(instagram[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{32}['\"'])", "Instagram API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(instagram[_-]?access[_-]?token\s*[:=]\s*['\"']IG[A-Za-z0-9_.-]+['\"'])", "Instagram Access Token", "CWE-798", "CRITICAL"),
    (r"(?i)(linkedin[_-]?client[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{16}['\"'])", "LinkedIn Client Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(linkedin[_-]?oauth[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]+['\"'])", "LinkedIn OAuth Token", "CWE-798", "HIGH"),
    (r"(?i)(tiktok[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{32}['\"'])", "TikTok API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(tiktok[_-]?client[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{32}['\"'])", "TikTok Client Secret", "CWE-798", "CRITICAL"),
]

# Messaging Patterns (15+)
MESSAGING_PATTERNS = [
    (r"(?i)(telegram[_-]?bot[_-]?token\s*[:=]\s*['\"']\d{8,10}:[A-Za-z0-9_-]{35}['\"'])", "Telegram Bot Token", "CWE-798", "CRITICAL"),
    (r"(?i)(telegram[_-]?api[_-]?hash\s*[:=]\s*['\"'][a-f0-9]{32}['\"'])", "Telegram API Hash", "CWE-798", "CRITICAL"),
    (r"(?i)(telegram[_-]?api[_-]?id\s*[:=]\s*['\"']?\d{5,8}['\"']?)", "Telegram API ID", "CWE-200", "LOW"),
    (r"(?i)(telegram[_-]?chat[_-]?id\s*[:=]\s*['\"']?-?\d{5,15}['\"']?)", "Telegram Chat ID", "CWE-200", "LOW"),
    (r"(?i)(bot\d+:[A-Za-z0-9_-]{35})", "Telegram Bot Token (Inline)", "CWE-798", "CRITICAL"),
    (r"(?i)(whatsapp[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{32}['\"'])", "WhatsApp API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(whatsapp[_-]?business[_-]?api[_-]?token\s*[:=]\s*['\"']EAA[A-Za-z0-9]+['\"'])", "WhatsApp Business API Token", "CWE-798", "CRITICAL"),
    (r"(?i)(vonage[_-]?api[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{16}['\"'])", "Vonage API Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(nexmo[_-]?api[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{16}['\"'])", "Nexmo API Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(messagebird[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{25}['\"'])", "MessageBird API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(slack[_-]?incoming[_-]?webhook[_-]?url\s*[:=]\s*['\"']https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+['\"'])", "Slack Incoming Webhook URL", "CWE-798", "HIGH"),
    (r"(?i)(teams[_-]?webhook[_-]?url\s*[:=]\s*['\"']https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9-]+@[a-z0-9-]+/IncomingWebhook/[a-z0-9]+/[a-z0-9-]+['\"'])", "Microsoft Teams Webhook URL", "CWE-798", "HIGH"),
    (r"(?i)(signal[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{32}['\"'])", "Signal API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(pusher[_-]?app[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{20}['\"'])", "Pusher App Key", "CWE-200", "MEDIUM"),
    (r"(?i)(vonage[_-]?api[_-]?key\s*[:=]\s*['\"'][a-f0-9]{8}['\"'])", "Vonage API Key", "CWE-798", "HIGH"),
]

# Payment Patterns (15+)
PAYMENT_PATTERNS = [
    (r"(?i)(paypal[_-]?client[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{80}['\"'])", "PayPal Client Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(paypal[_-]?access[_-]?token\s*[:=]\s*['\"']A21[A-Za-z0-9_-]+['\"'])", "PayPal Access Token", "CWE-798", "CRITICAL"),
    (r"(?i)(square[_-]?access[_-]?token\s*[:=]\s*['\"'][A-Za-z0-9_-]{43}['\"'])", "Square Access Token", "CWE-798", "CRITICAL"),
    (r"(?i)(square[_-]?application[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{43}['\"'])", "Square Application Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(sq0csp-[A-Za-z0-9_-]{40,50})", "Square Application Secret (Inline)", "CWE-798", "CRITICAL"),
    (r"(?i)(braintree[_-]?private[_-]?key\s*[:=]\s*['\"'][a-f0-9]{32}['\"'])", "Braintree Private Key", "CWE-798", "CRITICAL"),
    (r"(?i)(braintree[_-]?merchant[_-]?id\s*[:=]\s*['\"'][a-z0-9]{16}['\"'])", "Braintree Merchant ID", "CWE-200", "MEDIUM"),
    (r"(?i)(adyen[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9_]{48}['\"'])", "Adyen API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(razorpay[_-]?key[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{40}['\"'])", "Razorpay Key Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(coinbase[_-]?api[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{64}['\"'])", "Coinbase API Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(coinbase[_-]?webhook[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{64}['\"'])", "Coinbase Webhook Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(stripe[_-]?api[_-]?key\s*[:=]\s*['\"'](sk|rk)_(live|test)_[A-Za-z0-9]+['\"'])", "Stripe API Key Assignment", "CWE-798", "CRITICAL"),
    (r"(?i)(paypal[_-]?sandbox[_-]?client[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9]{80}['\"'])", "PayPal Sandbox Client Secret", "CWE-798", "HIGH"),
    (r"(?i)(adyen[_-]?client[_-]?key\s*[:=]\s*['\"']test_[A-Za-z0-9]{32}['\"'])", "Adyen Client Key", "CWE-798", "HIGH"),
    (r"(?i)(razorpay[_-]?key[_-]?id\s*[:=]\s*['\"']rzp_(test|live)_[A-Za-z0-9]{14}['\"'])", "Razorpay Key ID", "CWE-200", "MEDIUM"),
]

# Cryptocurrency Patterns (20+)
CRYPTO_PATTERNS = [
    (r"\b(5[HJK][1-9A-HJ-NP-Za-km-z]{49})\b", "Bitcoin Private Key (WIF uncompressed)", "CWE-798", "CRITICAL"),
    (r"\b(K[1-9A-HJ-NP-Za-km-z]{51})\b", "Bitcoin Private Key (WIF compressed)", "CWE-798", "CRITICAL"),
    (r"\b(L[1-9A-HJ-NP-Za-km-z]{51})\b", "Bitcoin Private Key (WIF compressed variant)", "CWE-798", "CRITICAL"),
    (r"\b(0x[a-fA-F0-9]{64})\b", "Ethereum Private Key", "CWE-798", "CRITICAL"),
    (r"\b(0x[a-fA-F0-9]{40})\b", "Ethereum Address", "CWE-200", "LOW"),
    (r"\b([13][1-9A-HJ-NP-Za-km-z]{26,33})\b", "Bitcoin Address", "CWE-200", "LOW"),
    (r"\b(bc1[a-z0-9]{39,59})\b", "Bitcoin Bech32 Address", "CWE-200", "LOW"),
    (r"(?i)(mnemonic\s*[:=]\s*['\"'][a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+['\"'])", "BIP39 Mnemonic/Seed Phrase", "CWE-798", "CRITICAL"),
    (r"(?i)(seed[_-]?phrase\s*[:=]\s*['\"'][a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+['\"'])", "Cryptocurrency Seed Phrase", "CWE-798", "CRITICAL"),
    (r"(?i)(private[_-]?key\s*[:=]\s*['\"']0x[a-fA-F0-9]{64}['\"'])", "Hardcoded Private Key (Hex)", "CWE-798", "CRITICAL"),
    (r"(?i)(coinmarketcap[_-]?api[_-]?key\s*[:=]\s*['\"'][a-f0-9-]{36}['\"'])", "CoinMarketCap API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(coingecko[_-]?api[_-]?key\s*[:=]\s*['\"']CG-[A-Za-z0-9]{28}['\"'])", "CoinGecko API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(etherscan[_-]?api[_-]?key\s*[:=]\s*['\"'][A-Z0-9]{34}['\"'])", "Etherscan API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(infura[_-]?project[_-]?secret\s*[:=]\s*['\"'][a-f0-9]{32}['\"'])", "Infura Project Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(alchemy[_-]?api[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9_-]{32}['\"'])", "Alchemy API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(blockchain[_-]?api[_-]?key\s*[:=]\s*['\"'][a-f0-9]{32}['\"'])", "Blockchain.com API Key", "CWE-798", "CRITICAL"),
    (r"(?i)(wallet[_-]?seed\s*[:=]\s*['\"'][a-z]+( [a-z]+){11,23}['\"'])", "Cryptocurrency Wallet Seed", "CWE-798", "CRITICAL"),
    (r"(?i)(crypto[_-]?private[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9+/=]{32,}['\"'])", "Crypto Private Key (Base64)", "CWE-798", "CRITICAL"),
    (r"(?i)(bitcoin[_-]?private[_-]?key\s*[:=]\s*['\"'][A-Za-z0-9]{51,52}['\"'])", "Bitcoin Private Key (Assignment)", "CWE-798", "CRITICAL"),
    (r"(?i)(ethereum[_-]?private[_-]?key\s*[:=]\s*['\"']0x[a-fA-F0-9]{64}['\"'])", "Ethereum Private Key (Assignment)", "CWE-798", "CRITICAL"),
]

# Generic Secret/Token Patterns (40+)
GENERIC_SECRET_PATTERNS = [
    (r"(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)", "JWT Token", "CWE-798", "HIGH"),
    (r"(?i)(jwt[_-]?secret\s*[:=]\s*['\"'][^'\"]{16,}['\"'])", "JWT Secret Key", "CWE-798", "CRITICAL"),
    (r"(?i)(jwt[_-]?private[_-]?key\s*[:=]\s*['\"']-----BEGIN (RSA |EC )?PRIVATE KEY-----['\"'])", "JWT Private Key", "CWE-798", "CRITICAL"),
    (r"(?i)(jwt[_-]?token\s*[:=]\s*['\"']eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*['\"'])", "JWT Token Assignment", "CWE-798", "HIGH"),
    (r"(?i)(api[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{20,}['\"'])", "Hardcoded API Key", "CWE-798", "HIGH"),
    (r"(?i)(api[_-]?secret\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{20,}['\"'])", "Hardcoded API Secret", "CWE-798", "HIGH"),
    (r"(?i)(client[_-]?secret\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,}['\"'])", "Hardcoded Client Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(client[_-]?id\s*[:=]\s*['\"'][a-zA-Z0-9_-]{10,}['\"'])", "Hardcoded Client ID", "CWE-200", "MEDIUM"),
    (r"(?i)(app[_-]?secret\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{20,}['\"'])", "Hardcoded App Secret", "CWE-798", "CRITICAL"),
    (r"(?i)(app[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{20,}['\"'])", "Hardcoded App Key", "CWE-798", "HIGH"),
    (r"(?i)(basic\s+[A-Za-z0-9+/]{20,}=*)", "HTTP Basic Auth Token", "CWE-798", "CRITICAL"),
    (r"(?i)(password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded Password", "CWE-798", "CRITICAL"),
    (r"(?i)(passwd\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded Password (Variant)", "CWE-798", "CRITICAL"),
    (r"(?i)(pwd\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded Password (Short)", "CWE-798", "CRITICAL"),
    (r"(?i)(admin[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded Admin Password", "CWE-798", "CRITICAL"),
    (r"(?i)(root[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded Root Password", "CWE-798", "CRITICAL"),
    (r"(?i)(db[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded DB Password", "CWE-798", "CRITICAL"),
    (r"(?i)(smtp[_-]?password\s*[:=]\s*['\"'][^'\"]{4,}['\"'])", "Hardcoded SMTP Password", "CWE-798", "CRITICAL"),
    (r"(?i)(auth[_-]?token\s*[:=]\s*['\"'][a-zA-Z0-9_\-\.]{20,}['\"'])", "Hardcoded Auth Token", "CWE-798", "HIGH"),
    (r"(?i)(access[_-]?token\s*[:=]\s*['\"'][a-zA-Z0-9_\-\.]{20,}['\"'])", "Hardcoded Access Token", "CWE-798", "HIGH"),
    (r"(?i)(refresh[_-]?token\s*[:=]\s*['\"'][a-zA-Z0-9_\-\.]{20,}['\"'])", "Hardcoded Refresh Token", "CWE-798", "HIGH"),
    (r"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{30,})", "Hardcoded Bearer Token", "CWE-798", "CRITICAL"),
    (r"(?i)(session[_-]?secret\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,}['\"'])", "Hardcoded Session Secret", "CWE-798", "CRITICAL"),
    (r"(-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)", "Hardcoded Private Key", "CWE-798", "CRITICAL"),
    (r"(-----BEGIN ENCRYPTED PRIVATE KEY-----)", "Hardcoded Encrypted Private Key", "CWE-798", "HIGH"),
    (r"(-----BEGIN PRIVATE KEY-----)", "Hardcoded PKCS#8 Private Key", "CWE-798", "CRITICAL"),
    (r"(?i)(secret[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,}['\"'])", "Hardcoded Secret Key", "CWE-798", "HIGH"),
    (r"(?i)(secret\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,}['\"'])", "Hardcoded Secret", "CWE-798", "HIGH"),
    (r"(?i)(encryption[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9+/=]{16,}['\"'])", "Hardcoded Encryption Key", "CWE-798", "CRITICAL"),
    (r"(?i)(master[_-]?key\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,}['\"'])", "Hardcoded Master Key", "CWE-798", "CRITICAL"),
    (r"(?i)(base64[_-]?encoded[_-]?secret\s*[:=]\s*['\"'][A-Za-z0-9+/]{40,}=*['\"'])", "Base64 Encoded Secret", "CWE-798", "HIGH"),
    (r"(?i)(oauth[_-]?token\s*[:=]\s*['\"'][a-zA-Z0-9_\-\.]{20,}['\"'])", "Hardcoded OAuth Token", "CWE-798", "HIGH"),
    (r"(?i)(csrf[_-]?token\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,}['\"'])", "Hardcoded CSRF Token", "CWE-798", "MEDIUM"),
    (r"(?i)(access_token=[a-zA-Z0-9_\-\.]{20,})", "OAuth Token in URL", "CWE-200", "HIGH"),
    (r"(?i)(token=[a-zA-Z0-9_\-\.]{20,})", "Token in URL Parameter", "CWE-200", "HIGH"),
    (r"(?i)(api_key=[a-zA-Z0-9_\-]{16,})", "API Key in URL Parameter", "CWE-200", "HIGH"),
    (r"(?i)(password=[^&\s]{4,})", "Password in URL Parameter", "CWE-200", "CRITICAL"),
]

# Injection Patterns (15+)
INJECTION_PATTERNS = [
    (r"(?i)(execute\s*\(\s*['\"'].*\$\{.*\}.*['\"']\s*\))", "SQL Injection via Template Literal", "CWE-89", "CRITICAL"),
    (r"(?i)(execute\s*\(\s*['\"'].*%s.*['\"']\s*%\s*\w+)", "SQL Injection via String Formatting", "CWE-89", "CRITICAL"),
    (r"(?i)(cursor\.execute\s*\(\s*f['\"'])", "SQL Injection with f-string", "CWE-89", "CRITICAL"),
    (r"(?i)(\.query\s*\(\s*['\"'].*\+.*\+\s*['\"'])", "SQL Injection in query()", "CWE-89", "CRITICAL"),
    (r"(?i)(\.raw\s*\(\s*['\"'].*\$\{.*['\"'])", "SQL Injection via .raw()", "CWE-89", "CRITICAL"),
    (r"(?i)(\.queryRaw\s*\(\s*['\"'].*\$\{.*['\"'])", "SQL Injection via queryRaw()", "CWE-89", "CRITICAL"),
    (r"(?i)(\$where\s*:\s*['\"'].*\+.*\+\s*['\"'])", "NoSQL Injection", "CWE-943", "HIGH"),
    (r"(?i)(\.find\s*\(\s*\{\s*\$where\s*:\s*\))", "NoSQL $where Injection", "CWE-943", "HIGH"),
    (r"(?i)(os\.system\s*\([^)]*[\+\%f]\s*\w+\))", "OS Command Injection", "CWE-78", "CRITICAL"),
    (r"(?i)(subprocess\.call\s*\(\s*['\"'].*\+.*\+\s*['\"'])", "Command Injection via Concatenation", "CWE-78", "CRITICAL"),
    (r"(?i)(subprocess\.Popen\s*\(\s*['\"'].*\+.*['\"'])", "Command Injection via Popen", "CWE-78", "CRITICAL"),
    (r"(?i)(subprocess\.run\s*\(\s*['\"'].*\+.*['\"'])", "Command Injection via run()", "CWE-78", "CRITICAL"),
    (r"(?i)(eval\s*\(\s*.*\$\{.*\}\s*\))", "Eval Injection", "CWE-94", "CRITICAL"),
    (r"(?i)(exec\s*\(\s*.*\$\{.*\}\s*\))", "Exec Injection", "CWE-94", "CRITICAL"),
    (r"(?i)(child_process\..*\(.*\+.*\+.*\))", "Command Injection (Node.js)", "CWE-78", "CRITICAL"),
    (r"(?i)(Runtime\.getRuntime\(\)\.exec\s*\(.*\+.*\+.*\))", "Command Injection (Java)", "CWE-78", "CRITICAL"),
    (r"(?i)(ProcessBuilder\s*\(\s*.*\+.*\+.*\))", "Command Injection via ProcessBuilder", "CWE-78", "CRITICAL"),
    (r"(?i)(xpath\s*\(\s*['\"'].*\+.*\+\s*['\"'])", "XPath Injection", "CWE-91", "HIGH"),
    (r"(?i)(search\s*\(\s*['\"'].*\+.*\+\s*['\"'])", "LDAP Injection", "CWE-90", "HIGH"),
    (r"(?i)(ldap_search\s*\(\s*.*\$.*\))", "LDAP Injection (Function)", "CWE-90", "HIGH"),
]

# XSS Patterns (12+)
XSS_PATTERNS = [
    (r"(?i)(innerHTML\s*=\s*.*\+.*\+.*)", "DOM-based XSS via innerHTML", "CWE-79", "HIGH"),
    (r"(?i)(outerHTML\s*=\s*.*\+.*\+.*)", "DOM-based XSS via outerHTML", "CWE-79", "HIGH"),
    (r"(?i)(document\.write\s*\(.*\+.*\+.*\))", "XSS via document.write", "CWE-79", "HIGH"),
    (r"(?i)(\.html\s*\(\s*.*\+.*\+.*\))", "XSS via jQuery .html()", "CWE-79", "HIGH"),
    (r"(?i)(dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*.*\+.*\+.*\})", "React XSS via dangerouslySetInnerHTML", "CWE-79", "HIGH"),
    (r"(?i)(dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*[^}]+\}\s*\})", "React XSS via dangerouslySetInnerHTML (Direct)", "CWE-79", "HIGH"),
    (r"(?i)(ng-bind-html\s*=\s*['\"'].*\{\{.*\}\}.*['\"'])", "Angular XSS via ng-bind-html", "CWE-79", "MEDIUM"),
    (r"(?i)(\{\{\{\s*.*\s*\}\}\})", "Handlebars unescaped expression", "CWE-79", "MEDIUM"),
    (r"(?i)(response\.write\s*\(\s*req\.(query|params|body))", "Reflected XSS", "CWE-79", "HIGH"),
    (r"(?i)(res\.send\s*\(\s*.*req\.(query|params|body))", "Reflected XSS via res.send", "CWE-79", "HIGH"),
    (r"(?i)(\.v-html\s*=\s*['\"'].*['\"'])", "Vue.js v-html XSS", "CWE-79", "MEDIUM"),
    (r"(?i)(document\.location\s*=\s*.*\+.*\+.*)", "Open Redirect via location", "CWE-601", "MEDIUM"),
]

# Path Traversal Patterns (10+)
PATH_TRAVERSAL_PATTERNS = [
    (r"(?i)(fs\.readFile\s*\(\s*req\.(params|query|body))", "Path Traversal via fs.readFile", "CWE-22", "HIGH"),
    (r"(?i)(fs\.readFileSync\s*\(\s*req\.(params|query|body))", "Path Traversal via fs.readFileSync", "CWE-22", "HIGH"),
    (r"(?i)(fs\.createReadStream\s*\(\s*req\.(params|query|body))", "Path Traversal via fs.createReadStream", "CWE-22", "HIGH"),
    (r"(?i)(sendFile\s*\(\s*req\.(params|query|body))", "Path Traversal via sendFile", "CWE-22", "HIGH"),
    (r"(?i)(res\.sendFile\s*\(\s*req\.(params|query|body))", "Path Traversal via res.sendFile", "CWE-22", "HIGH"),
    (r"(?i)(open\s*\(\s*.*\+.*\+.*\s*['\"']\s*\))", "Path Traversal via open()", "CWE-22", "HIGH"),
    (r"(?i)(FileInputStream\s*\(\s*.*\+.*req\.(params|query))", "Path Traversal in Java", "CWE-22", "HIGH"),
    (r"(?i)(new\s+File\s*\(\s*.*\+.*req\.(params|query))", "Path Traversal via File constructor", "CWE-22", "HIGH"),
    (r"(?i)(Paths\.get\s*\(\s*.*\+.*req\.(params|query))", "Path Traversal via Paths.get()", "CWE-22", "HIGH"),
    (r"(?i)(send_from_directory\s*\(\s*.*\+.*req\.(params|query))", "Path Traversal via send_from_directory", "CWE-22", "HIGH"),
]

# Crypto Weakness Patterns
CRYPTO_WEAKNESS_PATTERNS = [
    (r"(?i)(md5\s*\()", "Weak Hash Algorithm (MD5)", "CWE-327", "HIGH"),
    (r"(?i)(sha1\s*\()", "Weak Hash Algorithm (SHA1)", "CWE-327", "MEDIUM"),
    (r"(?i)(\bDES\b)", "Weak Encryption (DES)", "CWE-326", "HIGH"),
    (r"(?i)(\bRC4\b)", "Weak Encryption (RC4)", "CWE-326", "HIGH"),
    (r"(?i)(\bECB\b)", "Weak Encryption Mode (ECB)", "CWE-326", "MEDIUM"),
    (r"(?i)(Math\.random\s*\()", "Insecure Randomness", "CWE-330", "MEDIUM"),
    (r"(?i)(random\.random\s*\()", "Insecure Randomness", "CWE-330", "MEDIUM"),
    (r"(?i)(crypto\.createCipher\s*\(\s*['\"'][^'\"]+['\"']\s*,\s*['\"'][^'\"]+['\"'])", "Hardcoded Crypto Key", "CWE-798", "CRITICAL"),
    (r"(?i)(Cipher\.getInstance\s*\(\s*['\"']DES['\"'])", "Weak Java Crypto", "CWE-327", "HIGH"),
    (r"(?i)(\.createHash\s*\(\s*['\"']md5['\"'])", "MD5 Hash Usage", "CWE-327", "HIGH"),
    (r"(?i)(\.createHash\s*\(\s*['\"']sha1['\"'])", "SHA1 Hash Usage", "CWE-327", "MEDIUM"),
]

# CORS Patterns
CORS_PATTERNS = [
    (r"(?i)(Access-Control-Allow-Origin\s*:\s*\*)", "Permissive CORS Policy", "CWE-346", "MEDIUM"),
    (r"(?i)(cors\s*\(\s*\{[^}]*origin\s*:\s*['\"']\*['\"'])", "Permissive CORS (Express)", "CWE-346", "MEDIUM"),
    (r"(?i)(@CrossOrigin\s*\(\s*origins\s*=\s*['\"']\*['\"'])", "Permissive CORS (Spring)", "CWE-346", "MEDIUM"),
    (r"(?i)(res\.header\s*\(\s*['\"']Access-Control-Allow-Origin['\"']\s*,\s*['\"']\*['\"'])", "Permissive CORS Header", "CWE-346", "MEDIUM"),
]

# SSRF Patterns
SSRF_PATTERNS = [
    (r"(?i)(request\s*\(\s*.*req\.(params|query|body))", "Potential SSRF", "CWE-918", "HIGH"),
    (r"(?i)(urllib\.request\.urlopen\s*\(\s*.*\+.*\+.*\))", "Potential SSRF (Python)", "CWE-918", "HIGH"),
    (r"(?i)(requests\.(get|post)\s*\(\s*.*\+.*req\.(params|query))", "Potential SSRF (Python requests)", "CWE-918", "HIGH"),
    (r"(?i)(fetch\s*\(\s*.*\+.*\+.*\))", "Potential SSRF via fetch", "CWE-918", "MEDIUM"),
    (r"(?i)(axios\.(get|post)\s*\(\s*.*\+.*\+.*\))", "Potential SSRF via axios", "CWE-918", "MEDIUM"),
    (r"(?i)(curl\s+.*\$\w+)", "Potential SSRF via curl", "CWE-918", "HIGH"),
    (r"(?i)(urllib\.urlopen\s*\(\s*.*\+.*\))", "Potential SSRF (Python 2)", "CWE-918", "HIGH"),
]

# ReDoS Patterns
REDOS_PATTERNS = [
    (r"(?i)(\(\?i\)\(a\+\)\+b)", "ReDoS Vulnerable Regex", "CWE-400", "MEDIUM"),
    (r"(?i)(\(\?i\)\(.*\*.*\+.*\+.*\))", "ReDoS Vulnerable Regex Pattern", "CWE-400", "LOW"),
    (r"(?i)(\(.*\+.*\)\+.*\(.*\+.*\))", "ReDoS Nested Quantifiers", "CWE-400", "LOW"),
]

# Auth Patterns
AUTH_PATTERNS = [
    (r"(?i)(jwt\.verify\s*\(.*\{\s*algorithms\s*:\s*\[\s*['\"']none['\"'])", "JWT None Algorithm", "CWE-287", "CRITICAL"),
    (r"(?i)(verify\s*\(\s*.*\{\s*algorithm\s*:\s*['\"']HS256['\"'])", "JWT Weak Algorithm", "CWE-327", "MEDIUM"),
    (r"(?i)(session\s*\{\s*secure\s*:\s*false\})", "Insecure Session Cookie", "CWE-614", "HIGH"),
    (r"(?i)(cookie\s*\{\s*httpOnly\s*:\s*false\})", "Missing HttpOnly Cookie Flag", "CWE-1004", "MEDIUM"),
    (r"(?i)(res\.cookie\s*\(.*\{[^}]*secure\s*:\s*false\))", "Insecure Cookie (Express)", "CWE-614", "MEDIUM"),
    (r"(?i)(@csrf_exempt)", "CSRF Protection Exempted", "CWE-352", "HIGH"),
    (r"(?i)(csrf\s*=\s*false)", "CSRF Disabled", "CWE-352", "HIGH"),
]

# Header/Info Disclosure Patterns
HEADER_PATTERNS = [
    (r"(?i)(X-Powered-By)", "Information Disclosure via X-Powered-By Header", "CWE-200", "LOW"),
    (r"(?i)(Server\s*:\s*.*\d+\.\d+)", "Server Version Disclosure", "CWE-200", "LOW"),
]

# Combine all patterns
ALL_PATTERNS = (
    AWS_PATTERNS + GCP_PATTERNS + AZURE_PATTERNS + IBM_CLOUD_PATTERNS
    + API_KEY_PATTERNS + DATABASE_PATTERNS + CICD_PATTERNS
    + SOCIAL_PATTERNS + MESSAGING_PATTERNS + PAYMENT_PATTERNS
    + CRYPTO_PATTERNS + GENERIC_SECRET_PATTERNS
    + INJECTION_PATTERNS + XSS_PATTERNS + PATH_TRAVERSAL_PATTERNS
    + CRYPTO_WEAKNESS_PATTERNS + CORS_PATTERNS + SSRF_PATTERNS
    + REDOS_PATTERNS + AUTH_PATTERNS + HEADER_PATTERNS
)

# OWASP category mapping
OWASP_MAP = {
    "CWE-79": "A03", "CWE-89": "A03", "CWE-90": "A03", "CWE-91": "A03",
    "CWE-94": "A03", "CWE-78": "A03", "CWE-22": "A01", "CWE-23": "A01",
    "CWE-798": "A07", "CWE-287": "A07", "CWE-326": "A02", "CWE-327": "A02",
    "CWE-330": "A02", "CWE-918": "A10", "CWE-352": "A01", "CWE-346": "A05",
    "CWE-614": "A05", "CWE-1004": "A05", "CWE-200": "A05", "CWE-209": "A05",
    "CWE-400": "A04", "CWE-943": "A03", "CWE-95": "A03", "CWE-601": "A01",
    "CWE-97": "A03", "CWE-1104": "A06",
}


class CustomAIScanner:
    """
    Custom AI-powered pattern scanner.

    Detects security vulnerabilities using regex patterns, AST analysis,
    entropy-based detection, and heuristics. Does not require any external
    tools - runs purely in Python.

    Features 200+ secret patterns across cloud providers, APIs, databases,
    CI/CD systems, social media, messaging, payment, and cryptocurrency.
    """

    def __init__(self) -> None:
        """Initialize the custom AI scanner."""
        self.tool_name = "custom_ai"
        self.patterns = ALL_PATTERNS
        self.entropy_threshold = 4.0

    async def scan(self, source_path: str, scan_id: str) -> list:
        """
        Run the custom AI pattern scanner.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities found
        """
        logger.info("Running custom AI scanner on %s", source_path)
        vulnerabilities: list = []

        files = self._get_scannable_files(source_path)
        logger.info("Scanning %d files with pattern engine", len(files))

        for file_path in files:
            try:
                file_vulns = self._scan_file(file_path, scan_id, source_path)
                vulnerabilities.extend(file_vulns)

                if file_path.endswith(".py"):
                    ast_vulns = self._analyze_python_ast(file_path, scan_id, source_path)
                    vulnerabilities.extend(ast_vulns)

                # Entropy-based secret detection
                entropy_vulns = self._entropy_scan_file(file_path, scan_id, source_path)
                vulnerabilities.extend(entropy_vulns)

            except Exception as e:
                logger.debug("Error scanning %s: %s", file_path, e)

        # Scan .env files specifically
        env_vulns = self._scan_env_files(source_path, scan_id)
        vulnerabilities.extend(env_vulns)

        # Deduplicate
        vulnerabilities = self._deduplicate(vulnerabilities)

        logger.info("Custom AI scanner found %d issues", len(vulnerabilities))
        return vulnerabilities

    def _get_scannable_files(self, source_path: str) -> list:
        """Get list of files to scan."""
        files = []
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}

        for dirpath, dirnames, filenames in os.walk(source_path):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for filename in filenames:
                if any(filename.endswith(ext) for ext in [".min.js", ".min.css", ".map", ".lock"]):
                    continue
                if any(filename.endswith(ext) for ext in [
                    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
                    ".rb", ".php", ".c", ".cpp", ".cs", ".swift", ".kt",
                    ".rs", ".html", ".xml", ".json", ".yaml", ".yml", ".sh",
                    ".sql", ".cfg", ".ini", ".properties", ".gradle", ".tf",
                ]):
                    files.append(os.path.join(dirpath, filename))
                elif filename == ".env" or filename.startswith(".env."):
                    files.append(os.path.join(dirpath, filename))

        return files

    def _scan_file(self, file_path: str, scan_id: str, source_path: str) -> list:
        """Scan a single file for security patterns."""
        vulnerabilities: list = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return vulnerabilities

        relative_path = os.path.relpath(file_path, source_path)

        for pattern, title, cwe_id, severity in self.patterns:
            try:
                compiled = re.compile(pattern)
            except re.error:
                continue

            for line_num, line in enumerate(lines, 1):
                match = compiled.search(line)
                if match:
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                        if "CWE-798" not in cwe_id:
                            continue

                    code_snippet = read_file_snippet(file_path, line_num, context=2)

                    vuln = Vulnerability(
                        scan_id=scan_id,
                        file_path=relative_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        severity=severity,
                        category=title,
                        cwe_id=cwe_id,
                        cwe_name=CWE_MAPPING.get(cwe_id, title),
                        title=title,
                        description=f"{title} detected in {relative_path}:{line_num}",
                        code_snippet=code_snippet,
                        fix_suggestion=self._get_fix_suggestion(cwe_id, title),
                        tool_source=self.tool_name,
                        cvss_score=self._get_cvss_score(severity),
                        owasp_category=OWASP_MAP.get(cwe_id),
                        confidence="HIGH" if severity in ("CRITICAL", "HIGH") else "MEDIUM",
                        created_at=datetime.now(timezone.utc),
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _entropy_scan_file(self, file_path: str, scan_id: str, source_path: str) -> list:
        """Scan file for high-entropy strings that may be secrets."""
        vulnerabilities: list = []

        # Skip certain file types
        skip_extensions = {".json", ".md", ".lock", ".map", ".svg"}
        if any(file_path.endswith(ext) for ext in skip_extensions):
            return vulnerabilities

        # Skip known non-secret variable names
        false_positive_vars = {
            "version", "name", "title", "description", "message", "error",
            "content", "body", "data", "result", "value", "text", "html",
            "className", "style", "id", "type", "url", "path", "route",
            "template", "format", "pattern", "regex", "query", "filter",
            "sort", "order", "limit", "offset", "page", "count", "total",
            "status", "state", "mode", "action", "method", "handler",
        }

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return vulnerabilities

        relative_path = os.path.relpath(file_path, source_path)

        # Patterns that indicate potential secrets
        secret_indicators = [
            r"(?i)(token\s*[:=]\s*['\"'])([A-Za-z0-9_\-\.]{20,})['\"']",
            r"(?i)(key\s*[:=]\s*['\"'])([A-Za-z0-9_\-\.+/=]{20,})['\"']",
            r"(?i)(secret\s*[:=]\s*['\"'])([A-Za-z0-9_\-\.+/=]{16,})['\"']",
            r"(?i)(password\s*[:=]\s*['\"'])([^'\"]{8,})['\"']",
            r"(?i)(api[_-]?key\s*[:=]\s*['\"'])([A-Za-z0-9_\-]{16,})['\"']",
        ]

        for line_num, line in enumerate(lines, 1):
            for indicator_pattern in secret_indicators:
                matches = re.finditer(indicator_pattern, line)
                for match in matches:
                    var_name = match.group(1).lower().rstrip(r"\s*[:=]\s*[").rstrip(r"\s*[:=]\s*[")
                    secret_value = match.group(2)

                    # Skip false positives
                    if any(fp in var_name for fp in false_positive_vars):
                        continue
                    if len(secret_value) < 16:
                        continue

                    # Check entropy
                    if is_high_entropy(secret_value, self.entropy_threshold):
                        # Check if we already have a more specific match on this line
                        already_found = any(
                            v.line_number == line_num and v.file_path == relative_path
                            for v in vulnerabilities
                        )
                        if already_found:
                            continue

                        code_snippet = read_file_snippet(file_path, line_num, context=2)

                        vuln = Vulnerability(
                            scan_id=scan_id,
                            file_path=relative_path,
                            line_number=line_num,
                            column=match.start(2) + 1,
                            severity="HIGH",
                            category="High-Entropy Secret (Entropy Detection)",
                            cwe_id="CWE-798",
                            cwe_name=CWE_MAPPING.get("CWE-798", "Hardcoded Credentials"),
                            title=f"Potential Secret Detected via Entropy Analysis",
                            description=f"High-entropy string detected (entropy: {shannon_entropy(secret_value):.2f}) suggesting a hardcoded secret in {relative_path}:{line_num}",
                            code_snippet=code_snippet,
                            fix_suggestion="Move secrets to environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).",
                            tool_source=self.tool_name,
                            cvss_score=7.5,
                            owasp_category="A07",
                            confidence="MEDIUM",
                            created_at=datetime.now(timezone.utc),
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _scan_env_files(self, source_path: str, scan_id: str) -> list:
        """Scan .env files for exposed secrets."""
        vulnerabilities: list = []

        for dirpath, _, filenames in os.walk(source_path):
            if any(skip in dirpath for skip in [".git", "node_modules", "__pycache__"]):
                continue
            for filename in filenames:
                if filename == ".env" or filename.startswith(".env."):
                    file_path = os.path.join(dirpath, filename)
                    relative_path = os.path.relpath(file_path, source_path)

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                    except Exception:
                        continue

                    for line_num, line in enumerate(lines, 1):
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#"):
                            continue

                        # Check if it looks like a secret assignment
                        secret_keys = [
                            "api_key", "apikey", "api_secret", "secret_key", "secret",
                            "private_key", "auth_token", "access_token", "password",
                            "client_secret", "app_secret", "token", "key",
                        ]

                        if any(sk in stripped.lower() for sk in secret_keys):
                            if "=" in stripped:
                                value = stripped.split("=", 1)[1].strip()
                                if value and len(value) > 4:
                                    code_snippet = read_file_snippet(file_path, line_num, context=2)

                                    vuln = Vulnerability(
                                        scan_id=scan_id,
                                        file_path=relative_path,
                                        line_number=line_num,
                                        column=stripped.index("=") + 2,
                                        severity="HIGH",
                                        category="Secret in .env File",
                                        cwe_id="CWE-798",
                                        cwe_name=CWE_MAPPING.get("CWE-798", "Hardcoded Credentials"),
                                        title=f"Secret exposed in {filename}",
                                        description=f"Sensitive value found in {relative_path}:{line_num}. Ensure .env files are in .gitignore.",
                                        code_snippet=code_snippet,
                                        fix_suggestion="Add .env to .gitignore. Use a secrets manager for production. Never commit .env files.",
                                        tool_source=self.tool_name,
                                        cvss_score=7.0,
                                        owasp_category="A07",
                                        confidence="HIGH",
                                        created_at=datetime.now(timezone.utc),
                                    )
                                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_python_ast(self, file_path: str, scan_id: str, source_path: str) -> list:
        """Analyze Python file using AST for deeper analysis."""
        vulnerabilities: list = []
        relative_path = os.path.relpath(file_path, source_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
        except SyntaxError:
            return vulnerabilities
        except Exception:
            return vulnerabilities

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    if node.lineno:
                        code_snippet = read_file_snippet(file_path, node.lineno, context=2)
                        vuln = Vulnerability(
                            scan_id=scan_id,
                            file_path=relative_path,
                            line_number=node.lineno,
                            column=getattr(node, "col_offset", 0) + 1,
                            severity="CRITICAL",
                            category="Code Injection",
                            cwe_id="CWE-94",
                            cwe_name=CWE_MAPPING.get("CWE-94", "Code Injection"),
                            title=f"Dangerous {node.func.id}() Usage",
                            description=f"Use of {node.func.id}() can lead to arbitrary code execution",
                            code_snippet=code_snippet,
                            fix_suggestion="Avoid eval()/exec(). Use ast.literal_eval() for safe evaluation or refactor to avoid dynamic execution.",
                            tool_source=self.tool_name,
                            cvss_score=9.8,
                            owasp_category="A03",
                            confidence="HIGH",
                            created_at=datetime.now(timezone.utc),
                        )
                        vulnerabilities.append(vuln)

                if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
                    func_name = ""
                    if isinstance(node.func.value, ast.Name):
                        func_name = node.func.value.id
                    elif isinstance(node.func.value, ast.Attribute):
                        func_name = node.func.value.attr

                    if func_name in ("pickle", "cPickle", "yaml"):
                        if node.lineno:
                            code_snippet = read_file_snippet(file_path, node.lineno, context=2)
                            sev = "HIGH" if func_name in ("pickle", "cPickle") else "MEDIUM"
                            vuln = Vulnerability(
                                scan_id=scan_id,
                                file_path=relative_path,
                                line_number=node.lineno,
                                column=getattr(node, "col_offset", 0) + 1,
                                severity=sev,
                                category="Insecure Deserialization",
                                cwe_id="CWE-502",
                                cwe_name=CWE_MAPPING.get("CWE-502", "Deserialization"),
                                title=f"Insecure Deserialization via {func_name}.loads()",
                                description=f"Deserializing untrusted data with {func_name} can lead to remote code execution",
                                code_snippet=code_snippet,
                                fix_suggestion="Use safe serialization formats (JSON). Avoid pickle/yaml.loads() on untrusted data.",
                                tool_source=self.tool_name,
                                cvss_score=8.1 if func_name in ("pickle", "cPickle") else 6.5,
                                owasp_category="A08",
                                confidence="HIGH",
                                created_at=datetime.now(timezone.utc),
                            )
                            vulnerabilities.append(vuln)

            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        if any(keyword in name_lower for keyword in ["password", "secret", "api_key", "token"]):
                            if isinstance(node.value, ast.Constant):
                                if node.lineno:
                                    value = ""
                                    if isinstance(node.value, ast.Constant):
                                        value = str(node.value.value)
                                    elif hasattr(node.value, "s"):
                                        value = node.value.s

                                    if value and len(value) > 1:
                                        code_snippet = read_file_snippet(file_path, node.lineno, context=2)
                                        vuln = Vulnerability(
                                            scan_id=scan_id,
                                            file_path=relative_path,
                                            line_number=node.lineno,
                                            column=getattr(node, "col_offset", 0) + 1,
                                            severity="CRITICAL",
                                            category="Hardcoded Secret",
                                            cwe_id="CWE-798",
                                            cwe_name=CWE_MAPPING.get("CWE-798", "Hardcoded Credentials"),
                                            title=f"Hardcoded {target.id}",
                                            description=f"Variable '{target.id}' contains a hardcoded secret value",
                                            code_snippet=code_snippet,
                                            fix_suggestion="Use environment variables or a secrets manager (e.g., os.environ.get('SECRET_KEY'))",
                                            tool_source=self.tool_name,
                                            cvss_score=7.5,
                                            owasp_category="A07",
                                            confidence="HIGH",
                                            created_at=datetime.now(timezone.utc),
                                        )
                                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _deduplicate(self, vulnerabilities: list) -> list:
        """Deduplicate vulnerabilities by file_path + line_number + category."""
        seen: dict = {}
        for vuln in vulnerabilities:
            key = f"{vuln.file_path}:{vuln.line_number}:{vuln.category}"
            if key not in seen:
                seen[key] = vuln
            else:
                existing = seen[key]
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if severity_order.get(vuln.severity, 0) > severity_order.get(existing.severity, 0):
                    seen[key] = vuln
        return list(seen.values())

    def _get_cvss_score(self, severity: str) -> float:
        """Get approximate CVSS score based on severity."""
        scores = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return scores.get(severity.upper(), 5.0)

    def _get_fix_suggestion(self, cwe_id: str, title: str) -> str:
        """Get fix suggestion based on CWE ID."""
        suggestions = {
            "CWE-79": "Sanitize user input before rendering in HTML. Use frameworks that auto-escape (React, Vue). Implement Content-Security-Policy headers.",
            "CWE-89": "Use parameterized queries/prepared statements. Never concatenate user input into SQL queries. Use ORM frameworks.",
            "CWE-78": "Avoid shell commands with user input. Use subprocess with argument lists. Implement input validation and allowlisting.",
            "CWE-94": "Never use eval()/exec() with user input. Use ast.literal_eval() or safe parsing libraries. Implement code sandboxing.",
            "CWE-22": "Validate and sanitize file paths. Use allowlists for allowed directories. Avoid user input in file paths.",
            "CWE-798": "Move secrets to environment variables or secret managers (Vault, AWS Secrets Manager, Azure Key Vault). Use .env files excluded from version control. Rotate exposed credentials immediately.",
            "CWE-327": "Use strong hashing algorithms (SHA-256, bcrypt, Argon2). Avoid MD5 and SHA1 for security purposes.",
            "CWE-330": "Use cryptographically secure random number generators (secrets module in Python, crypto in Node.js).",
            "CWE-918": "Validate and sanitize URLs before fetching. Use allowlists for allowed domains. Disable redirects or validate redirect targets.",
            "CWE-352": "Implement CSRF tokens for state-changing operations. Use SameSite cookie attributes.",
            "CWE-346": "Specify exact allowed origins instead of '*'. Implement origin validation middleware.",
            "CWE-502": "Avoid deserializing untrusted data. Use JSON instead of pickle/yaml.loads(). Validate data before deserialization.",
            "CWE-326": "Use AES-256-GCM or ChaCha20-Poly1305. Avoid DES, RC4, and ECB mode.",
            "CWE-200": "Remove or restrict information disclosure. Use generic error messages in production.",
            "CWE-400": "Review regex patterns for ReDoS vulnerabilities. Use timeout-based regex matching.",
            "CWE-614": "Set Secure flag on all cookies. Use HTTPS only.",
            "CWE-1004": "Set HttpOnly flag on all cookies to prevent XSS theft.",
            "CWE-287": "Use strong authentication. Avoid 'none' JWT algorithm. Implement proper token validation.",
            "CWE-601": "Validate and sanitize redirect URLs. Use allowlists for redirect targets.",
        }
        return suggestions.get(cwe_id, f"Review and fix the {title} issue. Refer to CWE guidelines for {cwe_id}.")

    def is_available(self) -> bool:
        """Always available - no external dependencies."""
        return True
