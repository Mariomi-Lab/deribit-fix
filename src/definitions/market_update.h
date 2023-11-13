#pragma once

#include "basic_types.h"
#include "to_string.h"

// Enumerations required
enum class market_type_t { BID = 0, ASK = 1, TRADE = 2, INDEX = 3, SETTL_INDEX = 6};
enum class market_update_action_t { NEW = 0, CHANGE = 1, DELETE = 2 };

// to_string market_side_t
template <>
inline string to_string(market_type_t const &object) {
  switch (object) {
    case market_type_t::ASK:
      return "ASK";
      break;
    case market_type_t::BID:
      return "BID";
      break;
      case market_type_t::TRADE:
          return "TRADE";
          break;
      case market_type_t::INDEX:
          return "INDEX";
          break;
      case market_type_t::SETTL_INDEX:
          return "SETTL_INDEX";
          break;
  }
  BOOST_THROW_EXCEPTION(std::runtime_error(
      "to_string: Enumeration market_type_t has a wrong value"));
}

// to_string market_update_action_t
template <>
inline string to_string(market_update_action_t const &object) {
  switch (object) {
    case market_update_action_t::NEW:
      return "NEW";
      break;
    case market_update_action_t::CHANGE:
      return "CHANGE";
      break;
    case market_update_action_t::DELETE:
      return "DELETE";
      break;
  }
  BOOST_THROW_EXCEPTION(std::runtime_error(
      "to_string: Enumeration market_update_action_t has a wrong value"));
}

struct market_update_level_t {
  market_update_action_t update_type;
    market_type_t type;
    side_t side;
  volume_t level_volume;
  price_t level_price;
  optional<ptime> entryDate;
};

struct market_update_t {
  string symbol;

  optional<double> contract_multiplier;
  optional<string> underlying_symbol;
  optional<price_t> underlying_mid_price;

  vector<market_update_level_t> updates;

  friend std::ostream &operator<<(std::ostream &os,
                                  market_update_t const &update) {
    os << update.symbol << " : " ;
    for (auto const &update_level : update.updates) {
      os << to_string(update_level.entryDate) << " "
         << to_string(update_level.type) << " "
         << to_string(update_level.side) << " - "
         << update_level.level_price << " " << "#" << update_level.level_volume
         << " [" << to_string(update_level.update_type) << "]\t";
    }
    return os;
  }
};
