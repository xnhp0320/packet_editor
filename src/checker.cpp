#include "packet/checker.hpp"

#include <cstdlib>
#include <format>
#include <iostream>
#include <type_traits>
#include <utility>

namespace packet {

Checker::Checker(const TypeRegistry& type_validators,
                 const AttrNameRegistry& attr_names,
                 const AttrTypeRegistry& attr_types)
    : type_validators_(type_validators)
    , attr_names_(attr_names)
    , attr_types_(attr_types)
{
}

Checker::Checker(const Registry& registry)
    : Checker(registry.type_validators(), registry.attr_names(), registry.attr_types())
{
}

Checker::Result Checker::check(const Packet& packet) const {
    Result result{true, {}, {}};

    for (const auto& header : packet) {
        auto it = attr_names_.find(header.protocol);
        if (it == attr_names_.end()) {
            result.errors.push_back(
                std::format("unknown header: '{}'", header.protocol));
            result.ok = false;
            continue;
        }

        const auto& valid_attrs = it->second;
        auto type_it = attr_types_.find(header.protocol);

        for (const auto& attr : header.attributes) {
            if (!valid_attrs.contains(attr.name)) {
                result.warnings.push_back(
                    std::format("unknown attribute '{}' in header '{}'",
                                attr.name, header.protocol));
                continue;
            }

            if (attr.value.has_value() && type_it != attr_types_.end()) {
                auto type_name_it = type_it->second.find(attr.name);
                if (type_name_it != type_it->second.end()) {
                    auto value = evaluate(**attr.value);
                    if (std::holds_alternative<Packet>(value)) {
                        result.errors.push_back(
                            std::format("attribute '{}' in header '{}' requires a scalar value",
                                        attr.name, header.protocol));
                        result.ok = false;
                        continue;
                    }

                    auto scalar = std::visit([](auto&& v) -> ValueType {
                        using T = std::decay_t<decltype(v)>;
                        if constexpr (std::is_same_v<T, Packet>) {
                            return ValueType{int64_t{0}};
                        } else {
                            return ValueType{std::move(v)};
                        }
                    }, std::move(value));

                    auto validator_it = type_validators_.find(type_name_it->second);
                    if (validator_it != type_validators_.end()) {
                        auto err = validator_it->second->validate(scalar);
                        if (err) {
                            result.errors.push_back(
                                std::format("invalid '{}' in header '{}': {}",
                                            attr.name, header.protocol, *err));
                            result.ok = false;
                        }
                    }
                }
            } else if (attr.value.has_value()) {
                auto value = evaluate(**attr.value);
                if (std::holds_alternative<Packet>(value)) {
                    auto nested = check(std::get<Packet>(value));
                    result.warnings.insert(result.warnings.end(),
                                           nested.warnings.begin(),
                                           nested.warnings.end());
                    result.errors.insert(result.errors.end(),
                                         nested.errors.begin(),
                                         nested.errors.end());
                    result.ok = result.ok && nested.ok;
                }
            }
        }
    }

    return result;
}

void Checker::validate_or_exit(const Packet& packet) const {
    auto result = check(packet);

    for (const auto& w : result.warnings) {
        std::cerr << "WARNING: " << w << std::endl;
    }
    for (const auto& e : result.errors) {
        std::cerr << "ERROR: " << e << std::endl;
    }

    if (!result.ok) {
        std::exit(1);
    }

    if (!result.warnings.empty()) {
        std::cerr << std::format("{} warning(s) found.", result.warnings.size()) << std::endl;
    }
}

} // namespace packet
