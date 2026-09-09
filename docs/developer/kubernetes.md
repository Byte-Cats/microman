### Kubernetes Usage for your API

Micro-man has some kubernetes manifests that you can use to deploy your API to a kubernetes cluster. 

You can find them in the `deploy/k8` directory.

### Deploying to Kubernetes

To deploy your API to kubernetes, you will need to have a kubernetes cluster running. 

You can use minikube for local development.

Once you have a cluster running, you can deploy your API by running the following command:

```bash
kubectl apply -f deploy/k8
```

### Updating your API

To update your API, you will need to manually build a new docker image and bump the version in the `deploy/k8/deployment.yml` file.

Once you have done that, you can run the following command to update your API:

```bash
kubectl apply -f deploy/k8
```

### Health checks

The Deployment's container defines `livenessProbe` and `readinessProbe` checks against `GET /health` on port `6969` (the app's default `PORT`, see `app/settings.go`). Kubernetes uses these to know when a pod is up and ready to receive traffic, and to restart it if it stops responding. You can hit the same endpoint yourself once a pod is running:

```bash
kubectl port-forward deploy/deployment 6969:6969
curl http://localhost:6969/health
```

If you change the port the app listens on (via the `PORT` env var), update the container's `env`, `ports.containerPort`, the two probes' `port`, and `service.yml`'s `targetPort` together — they all need to agree.

### Deleting your API

To delete your API, you can run the following command:

```bash
kubectl delete -f deploy/k8
```

### Troubleshooting

If you are having issues with your API, you can run the following command to get the logs:

```bash
kubectl logs -f -l name=microman
```

### Scaling your API

To scale your API, you can run the following command:

```bash
kubectl scale deployment deployment --replicas=3
```

This will scale your API to 3 replicas.

### Deploying to AWS 

To deploy your API to AWS, you will need to have an AWS account and the AWS CLI installed.

You will also need to have a kubernetes cluster running in AWS.

You can use EKS for this.

... To be continued ...


## Byte Thoughts:

### Notes from Cloud Team


### Notes from Backend Team


### Notes from Dev Ops
technical thinking thoughts be bussin


