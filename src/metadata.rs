// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! OData `$metadata` introspection — parses CSDL XML into a flat property table.
//!
//! Works with both OData v4 (`http://docs.oasis-open.org/odata/ns/edm`) and
//! OData v2/v3 (`http://schemas.microsoft.com/ado/...`) CSDL documents.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::http::{self, HttpResponse, Method};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One row in the flat property table returned by `odata_metadata`.
#[derive(Debug, Clone)]
pub struct MetadataRow {
    /// Entity set name from the `EntityContainer` (NULL when the type has no
    /// directly mapped set, e.g. complex types used only as property types).
    pub entity_set: Option<String>,
    /// Unqualified entity/complex type name.
    pub entity_type: String,
    /// Property name.
    pub property_name: String,
    /// OData type string, e.g. `"Edm.String"`, `"Edm.Int32"`,
    /// or the navigation target type/role name.
    pub property_type: String,
    /// Whether the property accepts NULL values (OData default: true).
    pub nullable: bool,
    /// True when this property is part of the entity key.
    pub is_key: bool,
    /// True when this is a NavigationProperty rather than a scalar/complex Property.
    pub is_navigation: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch and parse the OData `$metadata` document at `url`.
///
/// Injects `Accept: application/xml` unless the caller already provides an
/// `Accept` header.  Returns an error string on HTTP failure or XML parse
/// error.
pub fn fetch_metadata(url: &str, headers: &[(String, String)]) -> Result<Vec<MetadataRow>, String> {
    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    if !all_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        all_headers.push(("Accept".into(), "application/xml".into()));
    }

    let resp: HttpResponse = http::execute(Method::Get, url, &all_headers, None);

    if resp.status != 200 {
        return Err(format!(
            "OData $metadata request failed: HTTP {} {}",
            resp.status, resp.reason
        ));
    }

    parse_metadata(&resp.body)
}

/// Parse a raw CSDL XML string into a flat list of [`MetadataRow`]s.
///
/// Public so callers can parse pre-fetched XML without a second HTTP round-trip.
pub fn parse_metadata(xml: &str) -> Result<Vec<MetadataRow>, String> {
    let mut entity_types: HashMap<String, EntityTypeDef> = HashMap::new();
    // entity-set name → qualified entity-type reference (e.g. "NS.Category")
    let mut entity_sets: HashMap<String, String> = HashMap::new();

    parse_csdl(xml, &mut entity_types, &mut entity_sets)?;

    // Build unqualified-type-name → entity-set-name lookup.
    // When two sets share the same type, the last one wins (unusual but valid).
    let type_to_set: HashMap<String, String> = entity_sets
        .iter()
        .map(|(set, type_ref)| {
            let unqualified = type_ref
                .split('.')
                .next_back()
                .unwrap_or(type_ref.as_str())
                .to_string();
            (unqualified, set.clone())
        })
        .collect();

    let mut rows: Vec<MetadataRow> = Vec::new();

    for (type_name, type_def) in &entity_types {
        let entity_set = type_to_set.get(type_name).cloned();
        for prop in &type_def.properties {
            rows.push(MetadataRow {
                entity_set: entity_set.clone(),
                entity_type: type_name.clone(),
                property_name: prop.name.clone(),
                property_type: prop.prop_type.clone(),
                nullable: prop.nullable,
                is_key: type_def.keys.contains(&prop.name),
                is_navigation: prop.is_navigation,
            });
        }
    }

    // Stable sort: entity_set (NULLs last), entity_type, key props first, alpha.
    rows.sort_by(|a, b| {
        // NULLs after named sets
        let set_cmp = match (&a.entity_set, &b.entity_set) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(x), Some(y)) => x.cmp(y),
        };
        set_cmp
            .then_with(|| a.entity_type.cmp(&b.entity_type))
            .then_with(|| b.is_key.cmp(&a.is_key)) // keys first
            .then_with(|| b.is_navigation.cmp(&a.is_navigation)) // nav props last
            .then_with(|| a.property_name.cmp(&b.property_name))
    });

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EntityTypeDef {
    keys: Vec<String>,
    properties: Vec<PropertyDef>,
}

struct PropertyDef {
    name: String,
    prop_type: String,
    nullable: bool,
    is_navigation: bool,
}

// ---------------------------------------------------------------------------
// CSDL parser
// ---------------------------------------------------------------------------

fn parse_csdl(
    xml: &str,
    entity_types: &mut HashMap<String, EntityTypeDef>,
    entity_sets: &mut HashMap<String, String>,
) -> Result<(), String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    // State
    let mut current_type: Option<String> = None; // EntityType or ComplexType name
    let mut in_key = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let tag = local_name(e.local_name().as_ref());

                match tag.as_str() {
                    // ---- type declarations ----
                    "EntityType" | "ComplexType" => {
                        if let Some(name) = attr(e, b"Name") {
                            current_type = Some(name.clone());
                            entity_types.entry(name).or_default();
                        }
                        in_key = false;
                    }

                    // ---- key declarations ----
                    "Key" => {
                        in_key = true;
                    }
                    "PropertyRef" if in_key => {
                        if let (Some(type_name), Some(prop_name)) =
                            (current_type.as_ref(), attr(e, b"Name"))
                        {
                            entity_types
                                .entry(type_name.clone())
                                .or_default()
                                .keys
                                .push(prop_name);
                        }
                    }

                    // ---- scalar properties ----
                    "Property" => {
                        if let Some(type_name) = current_type.as_ref() {
                            let name = attr(e, b"Name").unwrap_or_default();
                            if name.is_empty() {
                                continue;
                            }
                            let prop_type =
                                attr(e, b"Type").unwrap_or_else(|| "Edm.String".to_string());
                            // OData spec default: Nullable="true"
                            let nullable =
                                attr(e, b"Nullable").map(|v| v != "false").unwrap_or(true);
                            entity_types
                                .entry(type_name.clone())
                                .or_default()
                                .properties
                                .push(PropertyDef {
                                    name,
                                    prop_type,
                                    nullable,
                                    is_navigation: false,
                                });
                        }
                    }

                    // ---- navigation properties ----
                    // v4: Type="Collection(NS.Order)" or Type="NS.Order"
                    // v2: Relationship + ToRole attributes; no Type
                    "NavigationProperty" => {
                        if let Some(type_name) = current_type.as_ref() {
                            let name = attr(e, b"Name").unwrap_or_default();
                            if name.is_empty() {
                                continue;
                            }
                            let prop_type = attr(e, b"Type")
                                .or_else(|| attr(e, b"ToRole"))
                                .unwrap_or_else(|| "Navigation".to_string());
                            entity_types
                                .entry(type_name.clone())
                                .or_default()
                                .properties
                                .push(PropertyDef {
                                    name,
                                    prop_type,
                                    nullable: true,
                                    is_navigation: true,
                                });
                        }
                    }

                    // ---- entity container / entity sets ----
                    "EntitySet" => {
                        if let (Some(set_name), Some(type_ref)) =
                            (attr(e, b"Name"), attr(e, b"EntityType"))
                        {
                            entity_sets.insert(set_name, type_ref);
                        }
                    }

                    _ => {}
                }
            }

            Ok(Event::End(ref e)) => {
                let tag = local_name(e.local_name().as_ref());
                match tag.as_str() {
                    "EntityType" | "ComplexType" => {
                        current_type = None;
                        in_key = false;
                    }
                    "Key" => {
                        in_key = false;
                    }
                    _ => {}
                }
            }

            Ok(Event::Eof) => break,

            Err(e) => {
                return Err(format!(
                    "CSDL XML parse error at position {}: {e}",
                    reader.buffer_position()
                ))
            }

            _ => {} // Text, CData, Comment, PI, Decl — ignore
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// XML helpers
// ---------------------------------------------------------------------------

/// Return the local (non-namespaced) tag name as a `String`.
fn local_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Return the unescaped value of the named attribute, or `None` if absent.
fn attr(e: &quick_xml::events::BytesStart, name: &[u8]) -> Option<String> {
    for a in e.attributes().flatten() {
        if a.key.local_name().as_ref() == name {
            return a.unescape_value().ok().map(|v| v.into_owned());
        }
    }
    None
}
