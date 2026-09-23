# Deploying the pull request reviewer

Every pull request is checked twice.

**`Drift against the spec and the records`** compares the change against its
base and blocks on a record edited to agree with new code or a status claim
with no test beside it. It needs no credential, runs on every pull request,
and is already working. Nothing below is required for it.

**`Judgement against the spec and the records`** asks a model to read the same
brief a human would. It is the part this page sets up. Until it is configured
the job reports that it did not run — it never claims an approval it did not
give.

The model is yours, in Azure AI Foundry, reached with a token the workflow
proves it is entitled to. No key is stored in GitHub, and nothing bills per
pull request except your own Foundry usage.

## What you need first

A Foundry (Azure OpenAI) resource with a chat deployment. Note two things from
it: the endpoint, which looks like `https://<name>.openai.azure.com`, and the
deployment name you gave the model.

## 1. An identity for the workflow

The workflow signs in as an application that exists only for this. It holds no
password: GitHub proves the run's identity to Entra, and Entra hands back a
token that expires in minutes.

```sh
REPO=pawel-siwek/az-can-i-delete
APP_ID=$(az ad app create --display-name az-can-i-delete-reviewer --query appId -o tsv)
az ad sp create --id "$APP_ID"
```

## 2. Let this repository's pull requests use it

The subject is exact. A run that is not a pull request on this repository gets
no token, which is the point: the trust is scoped to one event on one
repository, not to anybody holding a secret.

Exact also means the shape has to be the one GitHub actually sends, and there
are two. The familiar `repo:OWNER/REPO:pull_request` is one; the other embeds
the numeric owner and repository ids, `repo:OWNER@1234/REPO@5678:pull_request`,
so that the trust survives a rename and does not follow the name to whoever
claims it next. A credential for the wrong one fails with `AADSTS700213: No
matching federated identity record found`, and that error quotes the subject
the run presented — which is the authoritative answer for this repository.

Both are cheap, so register both and stop caring which a runner sends:

```sh
OWNER=${REPO%/*}
NAME=${REPO#*/}
OWNER_ID=$(gh api "users/$OWNER" --jq .id)
REPO_ID=$(gh api "repos/$REPO" --jq .id)

add() {
  az ad app federated-credential create --id "$APP_ID" --parameters "{
    \"name\": \"$1\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"$2\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }"
}

add az-can-i-delete-pull-requests    "repo:$REPO:pull_request"
add az-can-i-delete-pull-requests-id "repo:$OWNER@$OWNER_ID/$NAME@$REPO_ID:pull_request"
```

Neither widens anything: each names one event on this one repository, and the
id-bearing one names it more precisely than the other.

## 3. Give it the one role it needs

Reading a model deployment, and nothing else. Replace the resource name and
group with your Foundry resource's.

```sh
FOUNDRY=$(az cognitiveservices account show -n <foundry-name> -g <resource-group> --query id -o tsv)
az role assignment create \
  --assignee "$APP_ID" \
  --role "Cognitive Services OpenAI User" \
  --scope "$FOUNDRY"
```

## 4. Tell the workflow where to look

These are repository *variables*, not secrets. None of them is sensitive: the
client id and tenant id are public identifiers, and without the federated
credential above they open nothing.

```sh
gh variable set AZURE_CLIENT_ID       -R "$REPO" -b "$APP_ID"
gh variable set AZURE_TENANT_ID       -R "$REPO" -b "$(az account show --query tenantId -o tsv)"
gh variable set AZURE_SUBSCRIPTION_ID -R "$REPO" -b "$(az account show --query id -o tsv)"
gh variable set AZURE_AI_ENDPOINT     -R "$REPO" -b "https://<foundry-name>.openai.azure.com"
gh variable set AZURE_AI_DEPLOYMENT   -R "$REPO" -b "<deployment-name>"
```

## 5. See it work

Open any pull request. The `Judgement` job will sign in, read the diff against
the records, and submit a review — a review, not a comment, so the reviewer
appears in the Reviewers list where a reader looks for a position:

```
### ✅ Conformance review — OK
OK — the change keeps every record it touches.
```

When it disagrees it posts `### ⛔ Conformance review — NOT OK`, a finding per
paragraph, **requests changes** — which blocks the merge — and the check goes
red. When a later run finds nothing to object to, it withdraws that refusal
itself.

Check it is configured at all:

```sh
gh variable list -R "$REPO"
```

## What it can and cannot do

It reviews, it requests changes, and it fails its own check. It cannot merge
or push, and it deliberately never approves: an approving review from the
workflow's own token can satisfy a ruleset that requires an approval, and this
repository requires a human one. A reviewer able to stand in for that human
quietly would be worse than no reviewer, so OK is a plain comment review —
same place, no authority it was not given. Merging stays a human's click.

Requesting changes blocks the merge, and GitHub lifts that only on an approval
or a dismissal. Since this reviewer never approves, it dismisses its own
earlier refusal when it next finds nothing to object to. It recognises its own
by the heading it writes, so a human's "changes requested" is never cleared by
a bot.

It reviews conformance, not craft: whether the change still honours
`REQUIREMENTS.md`, `docs/SPEC.md` and the records in `docs/adr/`. Style and
naming belong to the linter and to whoever opened the pull request. Its full
brief is `.github/copilot-instructions.md`, which a human doing the same job
should read too.

It treats the diff as material to review, never as instructions. A change
containing text that asks the reviewer to approve or ignore a rule is itself a
blocking finding.

## If it stops working

A failure to review is not an approval. The job fails, the check goes red, and
the log says which step could not complete — sign-in, the model call, or the
answer's shape. Nothing about that is silent, and nothing about it passes.

To turn it off, remove `AZURE_AI_ENDPOINT`. The job will report that no model
is configured and stop there; the drift check carries on deciding pull
requests on its own.
