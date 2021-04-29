package domainservices

import "github.com/hashicorp/terraform-plugin-sdk/helper/schema"

type Registration struct{}

// Name is the name of this Service
func (r Registration) Name() string {
	return "DomainServices"
}

// WebsiteCategories returns a list of categories which can be used for the sidebar
func (r Registration) WebsiteCategories() []string {
	return []string{
		"Active Directory Domain Services",
	}
}

// SupportedDataSources returns the supported Data Sources supported by this Service
func (r Registration) SupportedDataSources() map[string]*schema.Resource {
	return map[string]*schema.Resource{
		"azurerm_active_directory_domain_service": dataSourceActiveDirectoryDomainService(),
	}
}

// SupportedResources returns the supported Resources supported by this Service
func (r Registration) SupportedResources() map[string]*schema.Resource {
	return map[string]*schema.Resource{
		"azurerm_active_directory_domain_service":             resourceActiveDirectoryDomainService(),
		"azurerm_active_directory_domain_service_replica_set": resourceActiveDirectoryDomainServiceReplicaSet(),
	}
}
