#pragma once

#include "packet/type_validator.hpp"
#include "packet/value.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace packet {

enum class AttrValueKind {
    Scalar,
    Packet,
};

struct AttrSpec {
    std::string name;
    std::string type_name;
    std::optional<ConstructorValue> default_value;
    AttrValueKind value_kind = AttrValueKind::Scalar;
};

struct FieldSpec {
    std::string name;
    std::string type_name;
    size_t bit_offset = 0;
    size_t bit_width = 0;
    ConstructorValue default_value = uint64_t{0};
};

struct OptionSpec {
    std::string name;
    std::string type_name;
    AttrValueKind value_kind = AttrValueKind::Scalar;
    std::optional<ConstructorValue> default_value;
};

struct HeaderSpec {
    std::string protocol;
    std::vector<FieldSpec> fields;
    std::vector<OptionSpec> options;
    size_t bit_width = 0;
};

std::optional<std::string> validate_constructor_value(std::string_view name,
                                                      std::string_view type_name,
                                                      const ConstructorValue& value);

struct InferenceRule {
    std::string parent_header;
    std::string child_header;
    std::string target_field;
    ConstructorValue value;
};

using TypeRegistry = std::unordered_map<std::string, std::unique_ptr<TypeValidator>>;
using AttrNameRegistry = std::unordered_map<std::string, std::unordered_set<std::string>>;
using AttrTypeRegistry = std::unordered_map<std::string, std::unordered_map<std::string, std::string>>;
using HeaderSpecRegistry = std::unordered_map<std::string, HeaderSpec>;
using InferenceRuleRegistry =
    std::unordered_map<std::string, std::unordered_map<std::string, std::vector<InferenceRule>>>;

class Registry {
public:
    Registry();

    Registry& register_type(std::string type_name, std::unique_ptr<TypeValidator> validator);
    Registry& register_header(std::string protocol,
                              std::vector<AttrSpec> fields,
                              std::vector<AttrSpec> options = {});
    Registry& register_inference_rule(std::string parent_header,
                                      std::string child_header,
                                      std::string target_field,
                                      ConstructorValue value);

    const TypeRegistry& type_validators() const;
    const AttrNameRegistry& attr_names() const;
    const AttrTypeRegistry& attr_types() const;
    const HeaderSpecRegistry& header_specs() const;
    const HeaderSpec* find_header(std::string_view protocol) const;
    const std::vector<InferenceRule>* find_inference_rules(std::string_view parent_header,
                                                           std::string_view child_header) const;

private:
    TypeRegistry type_validators_;
    AttrNameRegistry attr_names_;
    AttrTypeRegistry attr_types_;
    HeaderSpecRegistry header_specs_;
    InferenceRuleRegistry inference_rules_;
};

} // namespace packet
