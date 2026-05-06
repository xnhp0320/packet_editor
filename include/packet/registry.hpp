#pragma once

#include "packet/type_validator.hpp"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace packet {

struct AttrSpec {
    std::string name;
    std::optional<std::string> type_name;
};

using TypeRegistry = std::unordered_map<std::string, std::unique_ptr<TypeValidator>>;
using AttrNameRegistry = std::unordered_map<std::string, std::unordered_set<std::string>>;
using AttrTypeRegistry = std::unordered_map<std::string, std::unordered_map<std::string, std::string>>;

class Registry {
public:
    Registry();

    Registry& register_type(std::string type_name, std::unique_ptr<TypeValidator> validator);
    Registry& register_header(std::string protocol, std::vector<AttrSpec> attrs);

    const TypeRegistry& type_validators() const;
    const AttrNameRegistry& attr_names() const;
    const AttrTypeRegistry& attr_types() const;

private:
    TypeRegistry type_validators_;
    AttrNameRegistry attr_names_;
    AttrTypeRegistry attr_types_;
};

} // namespace packet
