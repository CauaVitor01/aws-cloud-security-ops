# Segurança de Identidades e Monitoramento do Plano de Controle na AWS

🇺🇸 [English](README.md) | 🇧🇷 **Português**

Notas de estudo e laboratório prático sobre **ataques baseados em identidade na AWS** e como detectá-los com **CloudTrail** e **Splunk**.

> 📎 O relatório completo com prints e evidências está em [`monitoring_aws_logins.pdf`](monitoring_aws_logins.pdf).

## Visão geral

Monitorar o **plano de controle** (*control plane*) é o primeiro passo para proteger qualquer ambiente em nuvem, e a autenticação é a prioridade: **quem** está fazendo login, **de onde** e com **quais credenciais**. Este laboratório cobre os ataques de identidade mais comuns na AWS e as defesas contra eles.

## 1. Conceitos básicos de IAM

O IAM controla o acesso por quatro componentes: **Usuário**, **Grupo** (coleção de usuários), **Função/Role** (identidade temporária assumida por usuários ou serviços) e **Política** (documento JSON que define as permissões).

| Método de autenticação | Credenciais | Observações |
|---|---|---|
| Console de Gerenciamento | ID da conta, usuário, senha, MFA | Acesso pelo navegador |
| Chaves de acesso | ID + segredo de longo prazo | Acesso programático (CLI/SDK). Fixá-las no código é um alto risco de vazamento |
| Roles IAM + STS | Credenciais temporárias (poucas horas) | A forma segura de autorizar serviços como o EC2, sem chaves estáticas no código |

## 2. Logins no console

Força bruta contra o console é rara graças ao MFA, mas o **phishing** é muito usado para roubar credenciais (por exemplo, para viabilizar ransomware na nuvem). O CloudTrail registra toda tentativa, com sucesso ou não, como `ConsoleLogin`.

**Campos-chave**
- `errorMessage`: quando presente, a autenticação falhou
- `additionalEventData.MFAUsed`: deveria ser sempre `Yes`

**Padrões suspeitos:** logins com `root` (só em emergências), usuários de serviço entrando pelo console (deveriam usar chaves programáticas) e IPs anonimizadores (Tor/VPN).

```spl
index=* eventName=ConsoleLogin errorMessage="*"
| stats count by userIdentity.userName

index=* eventName=ConsoleLogin additionalEventData.MFAUsed="No"
| stats count by userIdentity.userName, sourceIPAddress
```

## 3. Chaves de acesso

Chaves de acesso vazadas são a causa mais comum de violações graves na nuvem. É frequente desenvolvedores guardarem as chaves em texto claro no código, em bancos de dados ou em arquivos `.env`, o que leva a envio em massa de phishing via Amazon SES ou roubo de dados seguido de extorsão.

O acesso programático **não gera `ConsoleLogin`**, porque cada chamada de API é validada individualmente. No console, uma ação costuma gerar uma cascata de eventos `Get`, `List` e `Describe`; pela CLI, o CloudTrail registra apenas o comando executado.

```spl
// Apenas ações feitas com chaves de acesso
index=* userIdentity.accessKeyId=AKIA*

// Alternativa: excluir sessões de console
index=* NOT userIdentity.sessionContext.attributes.creationDate=*
```

**Dicas de triagem**

| Verificação | Exemplo de alerta |
|---|---|
| Propósito | Um usuário de backup começando a provisionar instâncias EC2 |
| IP de origem | Uma conta de serviço de CI/CD aparecendo de outro provedor de nuvem (ex.: DigitalOcean) |
| User-Agent | Mudança abrupta de `aws-sdk-java` para `aws-cli`, sugerindo que as chaves foram importadas em outro lugar |

**Cenário de extorsão:** com uma chave vazada, o atacante lê um bucket S3 privado, apaga os objetos originais e envia uma nota de resgate. Para dimensionar o dano:

```spl
index=* userIdentity.userName="<USUARIO>"
| table userIdentity.accessKeyId, requestParameters.bucketName, eventName

index=* requestParameters.bucketName="<BUCKET>" eventName IN (DeleteObject, PutObject)
| table eventName, requestParameters.key
```

## 4. Roles IAM

Com uma role, os logs refletem uma identidade temporária:
- `userIdentity.type` é `AssumedRole`
- O `accessKeyId` começa com **`ASIA`** (credenciais temporárias do STS)
- O ARN da identidade termina com o **nome da sessão** (`...:assumed-role/NomeDaRole/NomeDaSessao`)

Por padrão, o nome da sessão é o ID da instância (EC2) ou o nome do usuário (usuários IAM). Um **nome de sessão personalizado** esconde o autor original, então é preciso rastrear o evento `AssumeRole`, que traz o usuário real (`userIdentity.userName`) e o nome da sessão (`requestParameters.roleSessionName`).

```spl
index=* eventName=AssumeRole
| table userIdentity.userName, requestParameters.roleSessionName
```

**Abuso:** se um atacante compromete uma instância EC2 (por exemplo, por força bruta de SSH), ele herda as permissões da role anexada. Foi assim que ocorreu o vazamento de dados da **Capital One**. Monitore mudanças repentinas de user-agent, procure chamadas de API **inéditas (*first-seen*)**, principalmente de exfiltração de dados, e proteja as cargas de trabalho que usam roles.

**Encadeamento de roles (*role chaining*):** quando um usuário assume uma role em uma conta e depois outra role em uma conta diferente, é preciso "desencadear" a investigação, seguindo cada evento `AssumeRole` até achar o usuário original.

## 5. Configurações incorretas no IAM

Muitos ataques começam meses ou anos antes da invasão, quando as condições para ela são criadas. O ideal é flagrar a mudança indevida no momento em que acontece.

| Eventos | O que procurar |
|---|---|
| `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy` | Política alterada, como uma `ReadOnlyAccess` sendo editada para permitir criar/excluir instâncias EC2 |
| `Attach[User\|Group\|Role]Policy`, `AddUserToGroup` | Excesso de privilégio, como `AdministratorAccess` concedida a um estagiário recém-contratado |
| `DeleteVirtualMFADevice`, `DeactivateMFADevice` | MFA desativado; só é legítimo se um novo MFA for registrado logo em seguida |
| `CreateAccessKey`, `UpdateAccessKey` | Chaves novas ou ativadas; confirme com a TI se era esperado |

**Persistência:** em um caso analisado pela Permiso (grupo de ameaças GUI-vil), os atacantes entraram com uma chave vazada e depois criaram uma **segunda chave de acesso** como backdoor, de modo que desativar a primeira não removeria o acesso deles.

```spl
index=* eventName=CreateAccessKey
| table _time, eventName, responseElements.accessKey.accessKeyId
```

**Dicas:** monitore toda a atividade do `root` e impeça a criação de chaves para ele, foque nos eventos `CreateAccessKey` e mantenha comunicação constante com a TI sobre configurações arriscadas.

## 6. Equivalentes em outras nuvens

| AWS | Google Cloud | Azure |
|---|---|---|
| Chaves de acesso | Chaves de conta de serviço | Credenciais de entidade de serviço |
| Roles IAM | Contas de serviço | Identidades gerenciadas |

A mesma lógica de caça a ameaças vale para ambientes multicloud.

## Habilidades praticadas

- Investigar eventos `ConsoleLogin`: falhas e logins sem MFA
- Separar sessões de console de acesso programático com chaves `AKIA` / `ASIA`
- Reconstruir um ataque de extorsão em S3 a partir de eventos do CloudTrail
- Desmascarar usuários por trás de nomes de sessão personalizados com `AssumeRole`
- Auditar mudanças no IAM e a criação de credenciais (`CreateAccessKey`)
