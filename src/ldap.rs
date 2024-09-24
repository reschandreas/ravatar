use crate::structs::Config;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError, SearchEntry};

pub(crate) async fn connect_ldap(config: &Config) -> Result<Ldap, LdapError> {
    let Some(ldap_config) = &config.ldap else {
        return Err(LdapError::UrlParsing {
            source: url::ParseError::EmptyHost,
        });
    };
    let (conn, mut ldap) = LdapConnAsync::with_settings(
        LdapConnSettings::new()
            .set_starttls(true)
            .set_no_tls_verify(true),
        &ldap_config.url,
    )
    .await?;
    ldap3::drive!(conn);
    let result = ldap
        .simple_bind(&ldap_config.bind_username, &ldap_config.bind_password)
        .await?;
    result.success()?;
    Ok(ldap)
}

pub(crate) async fn get_attributes_with_filter(config: Config, input: &str) -> Option<Vec<String>> {
    let mut ldap = connect_ldap(&config).await.unwrap();
    let ldap_config = config.ldap?;
    let filter = format!(
        "(&{}({}={}))",
        ldap_config.search_filter, ldap_config.input_attribute, input
    );
    let (search_result, _sr) = ldap
        .search(
            &ldap_config.base_dn,
            ldap3::Scope::Subtree,
            &filter,
            &ldap_config.target_attributes,
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    if search_result.is_empty() {
        return None;
    }
    let mut results = Vec::new();
    for entry in search_result {
        let matched = SearchEntry::construct(entry);
        for target_attribute in ldap_config.target_attributes.clone() {
            if let Some(value) = matched.attrs.get(&target_attribute) {
                results.push(value[0].clone());
                results.push(value[0].clone().to_ascii_lowercase());
                log::debug!("{} is also known as {}, adding lowercase as well", input, value[0]);
            }
        }
    }
    Some(results)
}
