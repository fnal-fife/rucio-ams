EXPERIMENT=dune
SERVER_CHART_VERSION := 38.0.2
DAEMON_CHART_VERSION := 38.0.1
UI_CHART_VERSION := 38.0.1

helm:
	helm repo add rucio https://rucio.github.io/helm-charts
	helm repo update

rucio-server: helm
	helm template fnal rucio/rucio-server --version=${SERVER_CHART_VERSION} --values=rucio/values-rucio-server.yaml > rucio/helm-rucio-server.yaml

rucio-daemons: helm
	helm template fnal rucio/rucio-daemons --version=${DAEMON_CHART_VERSION} --values=rucio/values-rucio-daemons.yaml > rucio/helm-rucio-daemons.yaml

rucio-webui: helm
	helm template fnal rucio/rucio-webui --version=${UI_CHART_VERSION} --values=rucio/values-rucio-webui.yaml > rucio/helm-rucio-webui.yaml

rucio: rucio-server rucio-daemons rucio-webui

get-secrets:
	mkdir -p rucio/etc/.secrets
	vault kv get --field=db-connstr okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/db-conn-str.txt
	vault kv get --field=hermes-rabbitmq okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/hermes-rabbitmq.json
	vault kv get --field=idpsecrets.json okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/idpsecrets.json
	vault kv get --field=rabbitmq-definitions.json okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/rabbitmq-definitions.json
	vault kv get --field=server-cafile okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/ca.pem
	vault kv get --field=server-hostcert okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/hostcert.pem
	vault kv get --field=server-hostkey okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/hostkey.pem
	vault kv get --field=sync_ferry_config.json okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/sync_ferry_config.json
	vault kv get --field=sync_justin_config.json okd/okdprod1/rucio-${EXPERIMENT}/rucio  > rucio/etc/.secrets/sync_justin_config.json

	mkdir -p pgbouncer/etc/.secrets
	vault kv get --field=db-target okd/okdprod1/rucio-${EXPERIMENT}/pgbouncer  > pgbouncer/etc/.secrets/db-target.json
	jq -r 'to_entries | map("\(.key)=\(.value)") | .[]' pgbouncer/etc/.secrets/db-target.json > pgbouncer/etc/.secrets/db-target.env

clean-secrets:
	rm -rf rucio/etc/.secrets
	rm -rf pgbouncer/etc/.secrets

run-dump: 
	kubectl kustomize .

dump: get-secrets rucio run-dump clean-secrets

run-apply:  
	kubectl apply -k .

#apply: get-secrets rucio run-apply clean-secrets
apply: rucio run-apply
