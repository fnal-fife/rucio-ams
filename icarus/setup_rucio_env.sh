# Environtment set up file for the icarus environment

export DOCKER_BUILDKIT=1
export FNAL_RUCIO_VERSION=1.22.7

# Make sure to set EXPERIMENT, FNAL_RUCIO_DIR, FNAL_EXP_RUCIO_CERT, FNAL_EXP_RUCIO_KEY, FNAL_EXP_RUCIO_CA_BUNDLE, FNAL_EXP_RUCIO_CERT_KEY_COMBINED
export EXPERIMENT=icarus
export FNAL_RUCIO_DIR=/cloud/login/bjwhite/dev/rucio/rucio-fnal

# Only the filenames are needed. The files should be resident in $FNAL_EXP_RUCIO_DEPLOYMENT_CONF_DIR/certs 
export FNAL_EXP_RUCIO_CERT=icaruspro.cert
export FNAL_EXP_RUCIO_KEY=icaruspro.key
export FNAL_EXP_RUCIO_CERT_KEY_COMBINED=icaruspro.combined
export FNAL_EXP_RUCIO_CA_BUNDLE=ca_bundle.pem
