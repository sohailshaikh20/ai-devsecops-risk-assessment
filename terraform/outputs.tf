output "deployment_name" {
  value = kubernetes_deployment.demo_app.metadata[0].name
}
