NAMESPACE	:= wueww-admin
BUILD_TEMPLATE	:= knative-php73-psr7

SERVICE_NAME	:= login
EXTRA_ENV	:= --env-secret mysql --env-secret jwt --env 'mysql-user=wueww' --env 'mysql-dbname=wueww' --env 'mysql-host=mysql'

upload:
	rm -rf upload.tmp && \
		mkdir upload.tmp && \
		cp -R bootstrap composer.* src upload.tmp/ && \
		tm deploy service $(SERVICE_NAME) -n $(NAMESPACE) -f upload.tmp --build-template $(BUILD_TEMPLATE) --env EVENT=API_GATEWAY $(EXTRA_ENV) --wait && \
		rm -rf upload.tmp

.PHONY: upload
