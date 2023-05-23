# Environtment set up file for the HYPOT environment
export RUCIO_AMS_DEV=true

export DOCKER_BUILDKIT=1
export RUCIO_AMS_VERSION=1.29.12

# Make sure to set EXPERIMENT, RUCIO_AMS_DIR, AMS_RUCIO_CERT, AMS_RUCIO_KEY, AMS_RUCIO_CA_BUNDLE
export RUCIO_AMS_DIR=/nashome/b/bjwhite/dev/rucio/rucio-ams

# Only the filenames are needed. The files should be resident in ${AMS_RUCIO_DEPLOYMENT_CONF_DIR}/certs 
export AMS_RUCIO_CERT=hypot-rucio.fnal.gov-cert.pem
export AMS_RUCIO_KEY=hypot-rucio.fnal.gov-key.pem
export AMS_RUCIO_CA_BUNDLE=ca_bundle.pem

export RUCIO_AMS_EXT_SERVER_IP=131.225.218.177
export RUCIO_AMS_EXT_AUTH_IP=131.225.218.176
export RUCIO_AMS_EXT_MSG_IP=131.225.218.174
export RUCIO_AMS_EXT_WEBUI_IP=131.225.218.175
