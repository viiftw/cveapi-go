package cveapi

// Response define response struct
type Response struct {
	Configurations struct {
		CVEDataVersion string `json:"CVE_data_version"`
		Nodes          []struct {
			CpeMatch []struct {
				Cpe23Uri   string `json:"cpe23Uri"`
				Vulnerable bool   `json:"vulnerable"`
			} `json:"cpe_match"`
			Operator string `json:"operator"`
		} `json:"nodes"`
	} `json:"configurations"`
	Cve struct {
		CVEDataMeta struct {
			Assigner string `json:"ASSIGNER"`
			ID       string `json:"ID"`
		} `json:"CVE_data_meta"`
		Affects struct {
			Vendor struct {
				VendorData []struct {
					Product struct {
						ProductData []struct {
							ProductName string `json:"product_name"`
							Version     struct {
								VersionData []struct {
									VersionAffected string `json:"version_affected"`
									VersionValue    string `json:"version_value"`
								} `json:"version_data"`
							} `json:"version"`
						} `json:"product_data"`
					} `json:"product"`
					VendorName string `json:"vendor_name"`
				} `json:"vendor_data"`
			} `json:"vendor"`
		} `json:"affects"`
		DataFormat  string `json:"data_format"`
		DataType    string `json:"data_type"`
		DataVersion string `json:"data_version"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
		Problemtype struct {
			ProblemtypeData []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"problemtype_data"`
		} `json:"problemtype"`
		References struct {
			ReferenceData []struct {
				Name      string   `json:"name"`
				Refsource string   `json:"refsource"`
				Tags      []string `json:"tags"`
				URL       string   `json:"url"`
			} `json:"reference_data"`
		} `json:"references"`
	} `json:"cve"`
	Impact struct {
		BaseMetricV2 struct {
			AcInsufInfo bool `json:"acInsufInfo"`
			CvssV2      struct {
				AccessComplexity      string  `json:"accessComplexity"`
				AccessVector          string  `json:"accessVector"`
				Authentication        string  `json:"authentication"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				VectorString          string  `json:"vectorString"`
				Version               string  `json:"version"`
			} `json:"cvssV2"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			Severity                string  `json:"severity"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
		BaseMetricV3 struct {
			CvssV3 struct {
				AttackComplexity      string  `json:"attackComplexity"`
				AttackVector          string  `json:"attackVector"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				Scope                 string  `json:"scope"`
				UserInteraction       string  `json:"userInteraction"`
				VectorString          string  `json:"vectorString"`
				Version               string  `json:"version"`
			} `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3"`
	} `json:"impact"`
	LastModifiedDate string `json:"lastModifiedDate"`
	PublishedDate    string `json:"publishedDate"`
}
