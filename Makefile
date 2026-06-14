.PHONY: build run stop clean logs dev prod

# Development commands
dev:
	docker-compose up --build

dev-bg:
	docker-compose up --build -d

# Production commands
prod:
	docker-compose -f docker-compose.prod.yml up --build -d

# Basic commands
build:
	docker build -t headerdoctor .

run:
	docker run -p 5000:5000 headerdoctor

stop:
	docker-compose down

clean:
	docker-compose down -v
	docker system prune -f

logs:
	docker-compose logs -f

# Health check
health:
	curl -f http://localhost:5000 || exit 1

# Database commands
redis-cli:
	docker-compose exec redis redis-cli

# Backup
backup:
	docker-compose exec redis redis-cli --rdb /data/backup.rdb

# Alpine version
build-alpine:
	docker build -f Dockerfile.alpine -t headerdoctor:alpine .

run-alpine:
	docker run -p 5000:5000 headerdoctor:alpine