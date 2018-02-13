
bin/ssso:
	go build -o bin/ssso .
build: bin/ssso	
	docker build --rm -t carlosmecha/ssso .

run: build
	docker run --rm -p "8080:80" carlosmecha/ssso

clean:
	rm -f bin/ssso

build-dev:
	go build -o _app/app ./_app/
	docker build --rm -t carlosmecha/ssso-app ./_app/
	docker build --rm -t carlosmecha/ssso-db ./_database
	docker build --rm -t carlosmecha/ssso-nginx ./_nginx
	
.PHONY: run, build, build-dev, clean