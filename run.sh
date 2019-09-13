#!/bin/bash
python -m twisted \
	casproxy \
		-p 'https://airflow.k8s.bard.edu/' \
		-c 'https://cas.k8s.bard.edu/cas/login' \
		-s 'https://cas.k8s.bard.edu/cas/serviceValidate' \
		-l 'https://cas.k8s.bard.edu/cas/logout' \
		--addCA='/home/hsartoris/tls/ipa-ca.crt' \
		-e 'ssl:8443:certKey=/home/hsartoris/tls/star_k8s_bard_edu/star_k8s_bard_edu.crt:privateKey=/home/hsartoris/tls/star_k8s_bard_edu/star_k8s_bard_edu.key' \
		-L '/logout'
