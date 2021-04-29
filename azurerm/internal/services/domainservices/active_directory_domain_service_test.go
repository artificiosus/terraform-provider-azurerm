package domainservices_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance/check"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/domainservices/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

// To generate a suitable cert for AADDS:
//
// openssl req -subj '/CN=*.never.gonna.shut.you.down/O=HashiCorp, Inc./ST=CA/C=US' -extensions san \
//   -new -newkey rsa:2048 -sha256 -days 36500 -nodes -x509 -keyout aadds.key -out aadds.crt \
//   -config <(echo "[req]\ndistinguished_name=req\nreq_extensions=v3_req\n[san]\nsubjectAltName=DNS:never.gonna.shut.you.down\n \
//                   [v3_req]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,nonRepudiation,digitalSignature,keyEncipherment\n \
//                   extendedKeyUsage=serverAuth")
//
// Then package as a pfx bundle:
//
// openssl pkcs12 -export -out "aadds.pfx" -inkey "aadds.key" -in "aadds.crt" -password pass:qwer5678 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES
//
// The configuration value is the base64 encoded representation of the resulting pkcs12 bundle:
//
// base64 <aadds.pfx

const (
	secureLdapCertificate = "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"
)

type ActiveDirectoryDomainServiceResource struct {
	adminPassword string
}

type ActiveDirectoryDomainServiceReplicaSetResource struct {
}

// Running all tests sequentially here in the same acctest (including the data source) since you can create only one
// AADDS resource per tenant, or per location, or per subscription, making parallel testing infeasible.
func TestAccActiveDirectoryDomainService(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_active_directory_domain_service", "test")
	replicaSetResourceName := "azurerm_active_directory_domain_service_replica_set.test_secondary"
	dataSourceData := acceptance.BuildTestData(t, "data.azurerm_active_directory_domain_service", "test")

	r := ActiveDirectoryDomainServiceResource{
		adminPassword: fmt.Sprintf("%s%s", "p@$$Wd", acctest.RandString(6)),
	}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.complete(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("deployment_id").Exists(),
				check.That(data.ResourceName).Key("initial_replica_set.0.domain_controller_ip_addresses.#").HasValue("2"),
				// check.That(data.ResourceName).Key("initial_replica_set.0.external_access_ip_address").Exists(),
				check.That(data.ResourceName).Key("initial_replica_set.0.service_status").HasValue("Running"),
			),
		},
		data.ImportStep("secure_ldap.0.pfx_certificate", "secure_ldap.0.pfx_certificate_password"),

		{
			Config: r.completeWithReplicaSet(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(replicaSetResourceName).ExistsInAzure(ActiveDirectoryDomainServiceReplicaSetResource{}),
				check.That(replicaSetResourceName).Key("domain_service_id").MatchesOtherKey(check.That(data.ResourceName).Key("id")),
				check.That(replicaSetResourceName).Key("location").HasValue(azure.NormalizeLocation(data.Locations.Secondary)),
				check.That(replicaSetResourceName).Key("subnet_id").MatchesOtherKey(check.That("azurerm_subnet.aadds_secondary").Key("id")),
				check.That(replicaSetResourceName).Key("domain_controller_ip_addresses.#").HasValue("2"),
				// check.That(replicaSetResourceName).Key("external_access_ip_address").Exists(),
				check.That(replicaSetResourceName).Key("service_status").HasValue("Running"),
			),
		},

		{
			Config: r.dataSource(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(dataSourceData.ResourceName).Key("filtered_sync_enabled").HasValue("false"),
				check.That(dataSourceData.ResourceName).Key("secure_ldap.#").HasValue("1"),
				check.That(dataSourceData.ResourceName).Key("secure_ldap.0.enabled").HasValue("false"),
				check.That(dataSourceData.ResourceName).Key("location").HasValue(azure.NormalizeLocation(data.Locations.Primary)),
				check.That(dataSourceData.ResourceName).Key("notifications.#").HasValue("1"),
				check.That(dataSourceData.ResourceName).Key("notifications.0.additional_recipients.#").HasValue("2"),
				check.That(dataSourceData.ResourceName).Key("notifications.0.notify_dc_admins").HasValue("true"),
				check.That(dataSourceData.ResourceName).Key("notifications.0.notify_global_admins").HasValue("true"),
				check.That(dataSourceData.ResourceName).Key("replica_sets.#").HasValue("2"),
				check.That(dataSourceData.ResourceName).Key("replica_sets.0.domain_controller_ip_addresses.#").HasValue("2"),
				check.That(dataSourceData.ResourceName).Key("replica_sets.0.location").Exists(),
				check.That(dataSourceData.ResourceName).Key("replica_sets.0.id").Exists(),
				check.That(dataSourceData.ResourceName).Key("replica_sets.0.service_status").Exists(),
				check.That(dataSourceData.ResourceName).Key("replica_sets.0.subnet_id").Exists(),
				check.That(dataSourceData.ResourceName).Key("replica_sets.1.domain_controller_ip_addresses.#").HasValue("2"),
				check.That(dataSourceData.ResourceName).Key("replica_sets.1.location").Exists(),
				check.That(dataSourceData.ResourceName).Key("replica_sets.1.id").Exists(),
				check.That(dataSourceData.ResourceName).Key("replica_sets.1.service_status").Exists(),
				check.That(dataSourceData.ResourceName).Key("replica_sets.1.subnet_id").Exists(),
				check.That(dataSourceData.ResourceName).Key("resource_forest.#").HasValue("0"),
				check.That(dataSourceData.ResourceName).Key("security.#").HasValue("1"),
				check.That(dataSourceData.ResourceName).Key("security.0.ntlm_v1_enabled").HasValue("true"),
				check.That(dataSourceData.ResourceName).Key("security.0.sync_kerberos_passwords").HasValue("true"),
				check.That(dataSourceData.ResourceName).Key("security.0.sync_ntlm_passwords").HasValue("true"),
				check.That(dataSourceData.ResourceName).Key("security.0.sync_on_prem_passwords").HasValue("true"),
				check.That(dataSourceData.ResourceName).Key("security.0.tls_v1_enabled").HasValue("true"),
				check.That(dataSourceData.ResourceName).Key("sku").HasValue("Enterprise"),
			),
		},

		{
			Config: r.complete(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("deployment_id").Exists(),
				check.That(data.ResourceName).Key("initial_replica_set.0.domain_controller_ip_addresses.#").HasValue("2"),
				check.That(data.ResourceName).Key("initial_replica_set.0.external_access_ip_address").Exists(),
				check.That(data.ResourceName).Key("initial_replica_set.0.service_status").HasValue("Running"),
			),
		},
		data.ImportStep("secure_ldap.0.pfx_certificate", "secure_ldap.0.pfx_certificate_password"),

		{
			Config:      r.requiresImport(data),
			ExpectError: acceptance.RequiresImportError(data.ResourceType),
		},
	})
}

func (ActiveDirectoryDomainServiceResource) Exists(ctx context.Context, client *clients.Client, state *terraform.InstanceState) (*bool, error) {
	id, err := parse.DomainServiceID(state.ID)
	if err != nil {
		return nil, err
	}

	resp, err := client.DomainServices.DomainServicesClient.Get(ctx, id.ResourceGroup, id.Name)
	if err != nil {
		return nil, fmt.Errorf("reading DomainService: %+v", err)
	}

	return utils.Bool(resp.ID != nil), nil
}

func (ActiveDirectoryDomainServiceReplicaSetResource) Exists(ctx context.Context, client *clients.Client, state *terraform.InstanceState) (*bool, error) {
	id, err := parse.DomainServiceReplicaSetID(state.ID)
	if err != nil {
		return nil, err
	}

	resp, err := client.DomainServices.DomainServicesClient.Get(ctx, id.ResourceGroup, id.DomainServiceName)
	if err != nil {
		return nil, fmt.Errorf("reading DomainService: %+v", err)
	}

	if resp.ReplicaSets == nil || len(*resp.ReplicaSets) == 0 {
		return nil, fmt.Errorf("DomainService response returned with nil or empty replicaSets")
	}

	for _, replica := range *resp.ReplicaSets {
		if replica.ReplicaSetID != nil && *replica.ReplicaSetID == id.ReplicaSetName {
			return utils.Bool(true), nil
		}
	}

	return utils.Bool(false), nil
}

func (r ActiveDirectoryDomainServiceResource) complete(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

provider "azuread" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-aadds-%[2]d"
  location = "%[1]s"

  tags = {
    DONOTDELETE = "1"
  }
}

resource "azurerm_virtual_network" "test" {
  name                = "acctestVnet-aadds-%[2]d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  address_space       = ["10.10.0.0/16"]
}

resource "azurerm_subnet" "aadds" {
  name                 = "acctestSubnet-aadds-%[2]d"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test.address_space.0, 8, 0)]
}

resource "azurerm_subnet" "workload" {
  name                 = "acctestSubnet-workload-%[2]d"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test.address_space.0, 8, 1)]
}

resource "azurerm_network_security_group" "aadds" {
  name                = "acctestNSG-aadds-%[2]d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  security_rule {
    name                       = "AllowSyncWithAzureAD"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowRD"
    priority                   = 201
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "CorpNetSaw"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowPSRemoting"
    priority                   = 301
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5986"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowLDAPS"
    priority                   = 401
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "636"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource azurerm_subnet_network_security_group_association "test" {
  subnet_id                 = azurerm_subnet.aadds.id
  network_security_group_id = azurerm_network_security_group.aadds.id
}

data "azuread_domains" "test" {
  only_initial = true
}

resource "azuread_service_principal" "test" {
  application_id = "2565bd9d-da50-47d4-8b85-4c97f669dc36" // published app for domain services
}

resource "azuread_group" "test" {
  name        = "AAD DC Administrators"
  description = "Delegated group to administer Azure AD Domain Services"
}

resource "azuread_user" "test" {
  user_principal_name = "acctestAADDSAdminUser-%[2]d@${data.azuread_domains.test.domains.0.domain_name}"
  display_name        = "acctestAADDSAdminUser-%[2]d"
  password            = "%[4]s"
}

resource "azuread_group_member" "test" {
  group_object_id  = azuread_group.test.object_id
  member_object_id = azuread_user.test.object_id
}

resource "azurerm_active_directory_domain_service" "test" {
  name                = "acctest-%[3]s"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  domain_name           = "never.gonna.shut.you.down"
  sku                   = "Enterprise"
  filtered_sync_enabled = false

  initial_replica_set {
    subnet_id = azurerm_subnet.aadds.id
  }

  notifications {
    additional_recipients = ["notifyA@example.net", "notifyB@example.org"]
    notify_dc_admins      = true
    notify_global_admins  = true
  }

  //secure_ldap {
  //  enabled                  = true
  //  external_access_enabled  = true
  //  pfx_certificate          = "%[5]s"
  //  pfx_certificate_password = "qwer5678"
  //}

  security {
    ntlm_v1_enabled         = true
    sync_kerberos_passwords = true
    sync_ntlm_passwords     = true
    sync_on_prem_passwords  = true
    tls_v1_enabled          = true
  }

  tags = {
    Environment = "test"
  }

  depends_on = [
    azuread_group.test,
    azuread_group_member.test,
    azuread_service_principal.test,
    azuread_user.test,
    azurerm_subnet_network_security_group_association.test,
  ]
}

resource "azurerm_virtual_network_dns_servers" "test" {
  virtual_network_id = azurerm_virtual_network.test.id
  dns_servers        = azurerm_active_directory_domain_service.test.initial_replica_set.0.domain_controller_ip_addresses
}
`, data.Locations.Primary, data.RandomInteger, data.RandomString, r.adminPassword, secureLdapCertificate)
}

func (r ActiveDirectoryDomainServiceResource) completeWithReplicaSet(data acceptance.TestData) string {
	return fmt.Sprintf(`
%[1]s

resource "azurerm_resource_group" "test_secondary" {
  name     = "acctestRG-aadds-secondary-%[4]d"
  location = "%[2]s"

  tags = {
    DONOTDELETE = "1"
  }
}

resource "azurerm_virtual_network" "test_secondary" {
  name                = "acctestVnet-aadds-secondary-%[4]d"
  location            = azurerm_resource_group.test_secondary.location
  resource_group_name = azurerm_resource_group.test_secondary.name
  address_space       = ["10.20.0.0/16"]
}

resource "azurerm_subnet" "aadds_secondary" {
  name                 = "acctestSubnet-aadds-secondary-%[4]d"
  resource_group_name  = azurerm_resource_group.test_secondary.name
  virtual_network_name = azurerm_virtual_network.test_secondary.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_secondary.address_space.0, 8, 0)]
}

resource "azurerm_subnet" "workload_secondary" {
  name                 = "acctestSubnet-workload-secondary-%[4]d"
  resource_group_name  = azurerm_resource_group.test_secondary.name
  virtual_network_name = azurerm_virtual_network.test_secondary.name
  address_prefixes     = [cidrsubnet(azurerm_virtual_network.test_secondary.address_space.0, 8, 1)]
}

resource "azurerm_network_security_group" "aadds_secondary" {
  name                = "acctestNSG-aadds-secondary-%[4]d"
  location            = azurerm_resource_group.test_secondary.location
  resource_group_name = azurerm_resource_group.test_secondary.name

  security_rule {
    name                       = "AllowSyncWithAzureAD"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowRD"
    priority                   = 201
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "CorpNetSaw"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowPSRemoting"
    priority                   = 301
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5986"
    source_address_prefix      = "AzureActiveDirectoryDomainServices"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowLDAPS"
    priority                   = 401
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "636"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource azurerm_subnet_network_security_group_association "test_secondary" {
  subnet_id                 = azurerm_subnet.aadds_secondary.id
  network_security_group_id = azurerm_network_security_group.aadds_secondary.id
}

resource "azurerm_virtual_network_peering" "test_primary_secondary" {
  name                      = "acctestVnet-aadds-primary-secondary-%[4]d"
  resource_group_name       = azurerm_virtual_network.test.resource_group_name
  virtual_network_name      = azurerm_virtual_network.test.name
  remote_virtual_network_id = azurerm_virtual_network.test_secondary.id

  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  allow_virtual_network_access = true
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_peering" "test_secondary_primary" {
  name                      = "acctestVnet-aadds-secondary-primary-%[4]d"
  resource_group_name       = azurerm_virtual_network.test_secondary.resource_group_name
  virtual_network_name      = azurerm_virtual_network.test_secondary.name
  remote_virtual_network_id = azurerm_virtual_network.test.id

  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  allow_virtual_network_access = true
  use_remote_gateways          = false
}

resource "azurerm_active_directory_domain_service_replica_set" "test_secondary" {
  domain_service_id = azurerm_active_directory_domain_service.test.id
  location          = azurerm_resource_group.test_secondary.location
  subnet_id         = azurerm_subnet.aadds_secondary.id

  depends_on = [
    azurerm_subnet_network_security_group_association.test_secondary,
    azurerm_virtual_network_peering.test_primary_secondary,
    azurerm_virtual_network_peering.test_secondary_primary,
  ]
}

resource "azurerm_virtual_network_dns_servers" "test_secondary" {
  virtual_network_id = azurerm_virtual_network.test_secondary.id
  dns_servers        = azurerm_active_directory_domain_service_replica_set.test_secondary.domain_controller_ip_addresses
}
`, r.complete(data), data.Locations.Secondary, data.Locations.Ternary, data.RandomInteger)
}

func (r ActiveDirectoryDomainServiceResource) dataSource(data acceptance.TestData) string {
	return fmt.Sprintf(`
%[1]s

data "azurerm_active_directory_domain_service" "test" {
  name                = azurerm_active_directory_domain_service.test.name
  resource_group_name = azurerm_active_directory_domain_service.test.resource_group_name
}
`, r.completeWithReplicaSet(data))
}

func (r ActiveDirectoryDomainServiceResource) requiresImport(data acceptance.TestData) string {
	return fmt.Sprintf(`
%[1]s

resource "azurerm_active_directory_domain_service" "import" {
  name                = azurerm_active_directory_domain_service.test.name
  location            = azurerm_active_directory_domain_service.test.location
  resource_group_name = azurerm_active_directory_domain_service.test.resource_group_name

  domain_name = azurerm_active_directory_domain_service.test.domain_name
  sku         = azurerm_active_directory_domain_service.test.sku

  initial_replica_set {
    subnet_id = azurerm_active_directory_domain_service.test.initial_replica_set.0.subnet_id
  }
}
`, r.complete(data))
}
