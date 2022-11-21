VENV=venv
ACTIVATE?=. ${VENV}/bin/activate;

dev:
	echo "-> Configure virtual environment and install development dependencies"
	./configure --dev

isort:
	@echo "-> Apply isort changes to ensure proper imports ordering"
	${VENV}/bin/isort .

black:
	@echo "-> Apply black code formatter"
	${VENV}/bin/black .

doc8:
	@echo "-> Run doc8 validation"
	@${ACTIVATE} doc8 --max-line-length 100 --ignore-path docs/_build/ --quiet docs/

valid: isort black

check:
	@echo "-> Run pycodestyle (PEP8) validation"
	@${ACTIVATE} pycodestyle --max-line-length=100 --exclude=etc,venv,lib,thirdparty,docs .
	@echo "-> Run isort imports ordering validation"
	@${ACTIVATE} isort --check-only .
	@echo "-> Run black validation"
	@${ACTIVATE} black --check .

clean:
	@echo "-> Clean the Python env"
	./configure --clean

test:
	@echo "-> Run the test suite"
	${ACTIVATE} pytest -vvs

