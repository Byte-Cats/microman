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

To update your API, you will need to manually build a new docker image and bump the version in the `deploy/k8/deployment.yaml` file.

Once you have done that, you can run the following command to update your API:

```bash
kubectl apply -f deploy/k8
```

### Deleting your API

To delete your API, you can run the following command:

```bash
kubectl delete -f deploy/k8
```

### Troubleshooting

If you are having issues with your API, you can run the following command to get the logs:

```bash
kubectl logs -f -l app=api
```

### Scaling your API

To scale your API, you can run the following command:

```bash
kubectl scale deployment api --replicas=3
```

This will scale your API to 3 replicas.

### Deploying to AWS 

To deploy your API to AWS, you will need to have an AWS account and the AWS CLI installed.

You will also need to have a kubernetes cluster running in AWS.

You can use EKS for this.

... To be continued ...



## Notes from our Devops Team


