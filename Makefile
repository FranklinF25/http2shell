.PHONY: lab lab-large lab-http
lab: ## Generate corpus and run the small-probe differential matrix (vuln vs fixed Node images)
	bash lab/run.sh

lab-large: ## Run the ~23 MB block-switch-exhaustion differential matrix
	bash lab/run-large.sh

lab-http: ## Run the HTTP-path scanner methodology against both images
	bash lab/run-http.sh
