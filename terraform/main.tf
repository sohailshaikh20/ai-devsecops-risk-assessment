terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}

# ==========================================
# Kubernetes Deployment (INTENTIONALLY RISKY)
# ==========================================

resource "kubernetes_deployment" "vulnerable_app" {

  metadata {
    name = "devsecops-demo-app"

    labels = {
      app = "demo"
    }
  }

  spec {

    replicas = 2

    selector {
      match_labels = {
        app = "demo"
      }
    }

    template {

      metadata {
        labels = {
          app = "demo"
        }
      }

      spec {

        container {

          name  = "demo-container"

          # VULNERABILITY 1
          # latest tag → version drift risk
          image = "nginx:latest"

          port {
            container_port = 80
          }

          # VULNERABILITY 2
          # container running as root
          security_context {
            run_as_user = 0
          }

          # VULNERABILITY 3
          # privileged container
          security_context {
            privileged = true
          }

          # VULNERABILITY 4
          # missing resource limits
          # (intentional for testing)

          env {
            name  = "ENV"
            value = "dev"
          }
        }
      }
    }
  }
}

# ==========================================
# Kubernetes Service
# ==========================================

resource "kubernetes_service" "vulnerable_service" {

  metadata {
    name = "devsecops-demo-service"
  }

  spec {

    selector = {
      app = "demo"
    }

    port {
      port        = 80
      target_port = 80
    }

    # VULNERABILITY 5
    # public exposure
    type = "LoadBalancer"
  }
}
