VENV=.venv
VENV_ACTIVATE=$(VENV)/bin/activate

.PHONY: venv install run run-auth generate-rsa-key clean

venv:
	python3 -m venv $(VENV)

install: venv
	. $(VENV_ACTIVATE) && pip install -r requirements.txt

run:
	. $(VENV_ACTIVATE) && uvicorn main:app --reload --host localhost --port 8081

generate-rsa-key:
	. $(VENV_ACTIVATE) && python -c "from main import generate_sample_rsa_key; print('Add this to your .env file as JWT_RSA_PRIVATE_KEY:'); print('JWT_RSA_PRIVATE_KEY=\"' + generate_sample_rsa_key().replace('\n', '\\n') + '\"')"

clean:
	rm -rf $(VENV)
	rm -f test.db