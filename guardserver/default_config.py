# Application Config
DEBUG = True
SECRET_KEY = "secretkeybro"

LDAP_USERNAME = ""
LDAP_PASSWORD = ""

AUTHENTICATION_REQUIRED = False

# LDAP Configuration
LDAP_DN = "cn=%s,ou=people,dc=example,dc=com"
LDAP_SERVER = ""
LDAP_OU = ""


# Elastic Search Configuration
ELASTIC_HOST = "localhost"
ELASTIC_PORT = "9200"
INDEX = "repoguard"
DOC_TYPE = "repoguard"

# Github Configuration
GITHUB_TOKEN = ""
ORG_NAME = ""