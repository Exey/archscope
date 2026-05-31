package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DetectTechFromImport maps an import path to a technology label.
// Used both by the scanner (go.mod pass) and by the report (per-file imports).
func DetectTechFromImport(imp string, techSet map[string]bool) {
	m := map[string]string{
		"google.golang.org/grpc":              "gRPC",
		"google.golang.org/protobuf":          "Protocol Buffers",
		"github.com/gin-gonic/gin":            "Gin",
		"github.com/labstack/echo":            "Echo",
		"github.com/gofiber/fiber":            "Fiber",
		"github.com/gorilla/mux":              "Gorilla Mux",
		"github.com/go-chi/chi":               "Chi",
		"gorm.io/gorm":                        "GORM",
		"gorm.io/driver/postgres":             "PostgreSQL",
		"github.com/jmoiron/sqlx":             "sqlx",
		"github.com/jackc/pgx":                "PostgreSQL",
		"github.com/lib/pq":                   "PostgreSQL",
		"github.com/go-redis/redis":           "Redis",
		"github.com/redis/go-redis":           "Redis",
		"go.mongodb.org/mongo-driver":         "MongoDB",
		"github.com/segmentio/kafka-go":       "Kafka",
		"github.com/IBM/sarama":               "Kafka",
		"github.com/nats-io/nats.go":          "NATS",
		"github.com/streadway/amqp":           "RabbitMQ",
		"github.com/rabbitmq/amqp091-go":      "RabbitMQ",
		"go.uber.org/zap":                     "Zap Logger",
		"github.com/sirupsen/logrus":          "Logrus",
		"log/slog":                            "slog",
		"go.opentelemetry.io/otel":            "OpenTelemetry",
		"github.com/prometheus/client_golang": "Prometheus",
		"github.com/elastic/go-elasticsearch": "Elasticsearch",
		"github.com/ClickHouse/clickhouse-go": "ClickHouse",
		"github.com/minio/minio-go":           "MinIO",
		"github.com/aws/aws-sdk-go":           "AWS SDK",
		"github.com/aws/aws-sdk-go-v2":        "AWS SDK",
		"cloud.google.com/go":                 "Google Cloud",
		"k8s.io/client-go":                    "Kubernetes Client",
		"github.com/hashicorp/consul":          "Consul",
		"github.com/hashicorp/vault":           "HashiCorp Vault",
		"go.etcd.io/etcd":                     "etcd",
		"github.com/golang-jwt/jwt":           "JWT",
		"github.com/spf13/cobra":              "Cobra CLI",
		"github.com/spf13/viper":              "Viper Config",
		"github.com/grpc-ecosystem/grpc-gateway": "gRPC Gateway",
		"github.com/99designs/gqlgen":         "gqlgen (GraphQL)",
		"github.com/golang-migrate/migrate":   "DB Migrations",
		"github.com/pressly/goose":            "Goose Migrations",
		"github.com/swaggo/swag":              "Swagger",
		"github.com/stretchr/testify":         "Testify",
		"github.com/docker/docker":            "Docker SDK",
	}
	for prefix, tech := range m {
		if strings.HasPrefix(imp, prefix) {
			techSet[tech] = true
			return
		}
	}
}

// ScanDockerCompose reads docker-compose files from root and immediate subdirs,
// plus go.mod and Makefile hints, returning service names and detected technologies.
func ScanDockerCompose(rootPath string) (services []string, technologies []string) {
	techSet := make(map[string]bool)
	svcSet := make(map[string]bool)

	searchDirs := []string{rootPath}
	entries, _ := os.ReadDir(rootPath)
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			searchDirs = append(searchDirs, filepath.Join(rootPath, e.Name()))
		}
	}

	candidates := []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
	for _, dir := range searchDirs {
		for _, name := range candidates {
			svcs, techs := parseDockerCompose(filepath.Join(dir, name))
			for _, s := range svcs {
				svcSet[s] = true
			}
			for _, t := range techs {
				techSet[t] = true
			}
		}
		for _, t := range scanGoMod(filepath.Join(dir, "go.mod")) {
			techSet[t] = true
		}
		for _, t := range scanMakefile(filepath.Join(dir, "Makefile")) {
			techSet[t] = true
		}
	}

	for s := range svcSet {
		services = append(services, s)
	}
	sort.Strings(services)
	for t := range techSet {
		technologies = append(technologies, t)
	}
	sort.Strings(technologies)
	return
}

func parseDockerCompose(path string) (services []string, technologies []string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	lines := strings.Split(string(content), "\n")
	inServices := false
	indent := 0
	techSet := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "services:" {
			inServices = true
			indent = countLeadingSpaces(line)
			continue
		}
		if !inServices || len(trimmed) == 0 || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lineIndent := countLeadingSpaces(line)
		if lineIndent == indent+2 && strings.HasSuffix(trimmed, ":") {
			services = append(services, strings.TrimSuffix(trimmed, ":"))
		}
		if strings.Contains(trimmed, "image:") {
			img := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
			img = strings.Trim(img, "\"'")
			if tech := extractTechFromImage(img); tech != "" {
				techSet[tech] = true
			}
		}
		upper := strings.ToUpper(trimmed)
		if strings.Contains(upper, "POSTGRES") || strings.Contains(upper, "PGHOST") || strings.Contains(trimmed, "5432") {
			techSet["PostgreSQL"] = true
		}
		if strings.Contains(upper, "REDIS") || strings.Contains(trimmed, "6379") {
			techSet["Redis"] = true
		}
		if strings.Contains(upper, "MONGO") || strings.Contains(trimmed, "27017") {
			techSet["MongoDB"] = true
		}
		if strings.Contains(upper, "KAFKA") || strings.Contains(trimmed, "9092") {
			techSet["Kafka"] = true
		}
		if strings.Contains(upper, "RABBIT") || strings.Contains(trimmed, "5672") {
			techSet["RabbitMQ"] = true
		}
	}
	for t := range techSet {
		technologies = append(technologies, t)
	}
	return
}

func scanGoMod(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	techMap := map[string]string{
		"github.com/jackc/pgx":                   "PostgreSQL",
		"github.com/lib/pq":                      "PostgreSQL",
		"gorm.io/driver/postgres":                "PostgreSQL",
		"github.com/go-redis/redis":              "Redis",
		"github.com/redis/go-redis":              "Redis",
		"go.mongodb.org/mongo-driver":            "MongoDB",
		"github.com/segmentio/kafka-go":          "Kafka",
		"github.com/IBM/sarama":                  "Kafka",
		"github.com/Shopify/sarama":              "Kafka",
		"github.com/nats-io/nats.go":             "NATS",
		"github.com/streadway/amqp":              "RabbitMQ",
		"github.com/rabbitmq/amqp091-go":         "RabbitMQ",
		"google.golang.org/grpc":                 "gRPC",
		"google.golang.org/protobuf":             "Protocol Buffers",
		"github.com/gin-gonic/gin":               "Gin",
		"github.com/labstack/echo":               "Echo",
		"github.com/gofiber/fiber":               "Fiber",
		"github.com/go-chi/chi":                  "Chi",
		"github.com/gorilla/mux":                 "Gorilla Mux",
		"gorm.io/gorm":                           "GORM",
		"github.com/jmoiron/sqlx":                "sqlx",
		"go.uber.org/zap":                        "Zap Logger",
		"github.com/sirupsen/logrus":             "Logrus",
		"go.opentelemetry.io/otel":               "OpenTelemetry",
		"github.com/prometheus/client_golang":    "Prometheus",
		"github.com/elastic/go-elasticsearch":    "Elasticsearch",
		"github.com/ClickHouse/clickhouse-go":    "ClickHouse",
		"github.com/minio/minio-go":              "MinIO",
		"github.com/aws/aws-sdk-go":              "AWS SDK",
		"github.com/aws/aws-sdk-go-v2":           "AWS SDK",
		"cloud.google.com/go":                    "Google Cloud",
		"k8s.io/client-go":                       "Kubernetes Client",
		"github.com/hashicorp/consul":             "Consul",
		"github.com/hashicorp/vault":              "HashiCorp Vault",
		"go.etcd.io/etcd":                        "etcd",
		"github.com/golang-jwt/jwt":              "JWT",
		"github.com/spf13/cobra":                 "Cobra CLI",
		"github.com/spf13/viper":                 "Viper Config",
		"github.com/grpc-ecosystem/grpc-gateway": "gRPC Gateway",
		"github.com/99designs/gqlgen":            "gqlgen (GraphQL)",
		"github.com/golang-migrate/migrate":      "DB Migrations",
		"github.com/pressly/goose":               "Goose Migrations",
		"github.com/swaggo/swag":                 "Swagger",
		"github.com/stretchr/testify":            "Testify",
		"github.com/docker/docker":               "Docker SDK",
	}
	seen := make(map[string]bool)
	var techs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for prefix, tech := range techMap {
			if strings.HasPrefix(line, prefix) && !seen[tech] {
				techs = append(techs, tech)
				seen[tech] = true
			}
		}
	}
	return techs
}

func scanMakefile(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := strings.ToLower(string(content))
	hints := map[string]string{
		"protoc": "Protocol Buffers", "grpc": "gRPC", "postgres": "PostgreSQL",
		"psql": "PostgreSQL", "redis-cli": "Redis", "mongo": "MongoDB",
		"kafka": "Kafka", "rabbitmq": "RabbitMQ", "nats": "NATS",
		"docker": "Docker", "kubectl": "Kubernetes", "helm": "Helm",
		"swagger": "Swagger", "migrate": "DB Migrations",
	}
	seen := make(map[string]bool)
	var techs []string
	for kw, tech := range hints {
		if strings.Contains(s, kw) && !seen[tech] {
			techs = append(techs, tech)
			seen[tech] = true
		}
	}
	return techs
}

func countLeadingSpaces(s string) int {
	n := 0
	for _, ch := range s {
		if ch == ' ' {
			n++
		} else if ch == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

func extractTechFromImage(image string) string {
	imgLower := strings.ToLower(image)
	techMap := map[string]string{
		"postgres": "PostgreSQL", "postgresql": "PostgreSQL",
		"mysql": "MySQL", "mariadb": "MariaDB",
		"mongo": "MongoDB", "redis": "Redis", "memcached": "Memcached",
		"rabbitmq": "RabbitMQ", "kafka": "Kafka", "zookeeper": "Zookeeper",
		"elasticsearch": "Elasticsearch", "opensearch": "OpenSearch",
		"kibana": "Kibana", "grafana": "Grafana", "prometheus": "Prometheus",
		"jaeger": "Jaeger", "nginx": "NGINX", "envoy": "Envoy",
		"consul": "Consul", "vault": "HashiCorp Vault", "nats": "NATS",
		"etcd": "etcd", "minio": "MinIO", "clickhouse": "ClickHouse",
		"influxdb": "InfluxDB", "temporal": "Temporal", "keycloak": "Keycloak",
		"traefik": "Traefik", "caddy": "Caddy", "localstack": "LocalStack",
		"cassandra": "Cassandra",
	}
	for key, tech := range techMap {
		if strings.Contains(imgLower, key) {
			return tech
		}
	}
	return ""
}

// DevOpsTool is a detected DevOps tool with its display name and icon.
type DevOpsTool struct {
	Name string
	Icon string
}

// ScanDevOps walks rootPath (up to 2 levels deep) looking for DevOps
// artefacts: Dockerfiles, Helm charts, Kubernetes manifests, CI configs,
// Terraform, Ansible, and build scripts. Returns detected tools in stable order.
func ScanDevOps(rootPath string) []DevOpsTool {
	seen := map[string]bool{}
	add := func(name string) { seen[name] = true }

	// walk at most 2 levels deep
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			nameLow := strings.ToLower(name)
			full := filepath.Join(dir, name)

			if e.IsDir() {
				switch nameLow {
				case ".github":
					// check for workflows subdir
					if _, err := os.Stat(filepath.Join(full, "workflows")); err == nil {
						add("GitHub Actions")
					}
				case ".circleci":
					add("CircleCI")
				case "terraform", ".terraform":
					add("Terraform")
				case "ansible":
					add("Ansible")
				case "helm", "charts":
					add("Helm")
				case "k8s", "kubernetes", "kube", "manifests", "deploy", "deployments", "infra", "infrastructure":
					add("Kubernetes")
				case "packer":
					add("Packer")
				case "vagrant":
					add("Vagrant")
				}
				if depth < 2 && !strings.HasPrefix(name, ".") &&
					name != "node_modules" && name != "vendor" {
					walk(full, depth+1)
				}
				continue
			}

			// files
			switch nameLow {
			case "dockerfile", "containerfile":
				add("Docker")
			case ".gitlab-ci.yml", ".gitlab-ci.yaml":
				add("GitLab CI")
			case "jenkinsfile":
				add("Jenkins")
			case "bitbucket-pipelines.yml":
				add("Bitbucket Pipelines")
			case "appveyor.yml":
				add("AppVeyor")
			case ".travis.yml":
				add("Travis CI")
			case "azure-pipelines.yml", "azure-pipelines.yaml":
				add("Azure Pipelines")
			case "buildkite.yml", "buildkite.yaml", ".buildkite":
				add("Buildkite")
			case "skaffold.yaml", "skaffold.yml":
				add("Skaffold")
				add("Kubernetes")
			case "tiltfile":
				add("Tilt")
			case "chart.yaml", "chart.yml":
				add("Helm")
			}

			// extension-based
			switch filepath.Ext(nameLow) {
			case ".tf", ".tfvars":
				add("Terraform")
			}

			// name patterns
			if strings.HasPrefix(nameLow, "dockerfile.") || strings.HasSuffix(nameLow, ".dockerfile") {
				add("Docker")
			}
			if strings.HasPrefix(nameLow, "docker-compose") {
				add("Docker Compose")
			}
			if strings.HasSuffix(nameLow, "-values.yaml") || strings.HasSuffix(nameLow, "-values.yml") {
				add("Helm")
			}
			// k8s manifests heuristic: yaml files in infra-like dirs
			if (filepath.Ext(nameLow) == ".yaml" || filepath.Ext(nameLow) == ".yml") && depth > 0 {
				parentLow := strings.ToLower(filepath.Base(dir))
				if parentLow == "k8s" || parentLow == "kubernetes" || parentLow == "kube" ||
					parentLow == "manifests" || parentLow == "deploy" || parentLow == "deployments" {
					add("Kubernetes")
				}
			}
		}
	}
	walk(rootPath, 0)

	// Also pull from Makefile/docker-compose hints already in seen techs.
	// (Docker Compose already handled by ScanDockerCompose; supplement here.)
	if _, err := os.Stat(filepath.Join(rootPath, "docker-compose.yml")); err == nil {
		add("Docker Compose")
	}
	if _, err := os.Stat(filepath.Join(rootPath, "compose.yml")); err == nil {
		add("Docker Compose")
	}

	icons := map[string]string{
		"Docker":             "🐳",
		"Docker Compose":     "🐙",
		"Kubernetes":         "☸️",
		"Helm":               "⛵",
		"Terraform":          "🏗️",
		"Ansible":            "🤖",
		"GitHub Actions":     "⚙️",
		"GitLab CI":          "🦊",
		"Jenkins":            "🏗️",
		"CircleCI":           "⭕",
		"Travis CI":          "🔄",
		"Azure Pipelines":    "🔷",
		"Bitbucket Pipelines":"🪣",
		"Buildkite":          "🏗️",
		"Skaffold":           "🚀",
		"Tilt":               "🔥",
		"Packer":             "📦",
		"Vagrant":            "📦",
	}
	order := []string{
		"Docker", "Docker Compose", "Kubernetes", "Helm", "Terraform", "Ansible",
		"GitHub Actions", "GitLab CI", "Jenkins", "CircleCI", "Travis CI",
		"Azure Pipelines", "Bitbucket Pipelines", "Buildkite", "Skaffold", "Tilt",
		"Packer", "Vagrant",
	}
	var out []DevOpsTool
	for _, name := range order {
		if seen[name] {
			icon := icons[name]
			if icon == "" {
				icon = "🔧"
			}
			out = append(out, DevOpsTool{name, icon})
		}
	}
	return out
}
