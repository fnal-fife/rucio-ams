EXPERIMENT=int
SERVER_CHART_VERSION := 38.0.0
DAEMON_CHART_VERSION := 38.0.0
UI_CHART_VERSION := 38.0.0

helm:
	helm repo add rucio https://rucio.github.io/helm-charts
	helm repo update

rucio-server: helm
	helm template fnal rucio/rucio-server --version=${SERVER_CHART_VERSION} --values=rucio/values-rucio-server.yaml > rucio/helm-rucio-server.yaml

rucio-daemons: helm
	helm template fnal rucio/rucio-daemons --version=${DAEMON_CHART_VERSION} --values=rucio/values-rucio-daemons.yaml > rucio/helm-rucio-daemons.yaml

rucio-ui: helm
	helm template fnal rucio/rucio-webui --version=${UI_CHART_VERSION} --values=rucio/values-rucio-ui.yaml > rucio/helm-rucio-ui.yaml

rucio: rucio-server rucio-daemons rucio-ui

# get-secrets:
# 	mkdir -p rucio/etc/.secrets
# 	vault kv get --field=${EXPERIMENT}-server-hostkey secret/rucio/${EXPERIMENT}-rucio/rucio  > rucio/etc/.secrets/hostkey.pem
# 	vault kv get --field=${EXPERIMENT}-server-hostcert secret/rucio/${EXPERIMENT}-rucio/rucio  > rucio/etc/.secrets/hostcert.pem
# 	vault kv get --field=${EXPERIMENT}-server-cafile secret/rucio/${EXPERIMENT}-rucio/rucio  > rucio/etc/.secrets/ca.pem
# 	vault kv get --field=${EXPERIMENT}-db-conn-str secret/rucio/${EXPERIMENT}-rucio/rucio  > rucio/etc/.secrets/db-conn-str.txt
# 	curl https://raw.githubusercontent.com/rucio/rucio/master/etc/automatix.json > rucio/etc/.secrets/automatix.json

#clean-secrets:
#	rm -rf rucio/etc/.secrets

run-dump: 
	kubectl kustomize .

dump: get-secrets rucio run-dump clean-secrets

run-apply:  
	kubectl apply -k .

#apply: get-secrets rucio run-apply clean-secrets
apply: rucio run-apply
