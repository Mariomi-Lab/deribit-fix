#include "quickfix.h"

#include "quickfix_log_replayer.h"

#include "base64/base64.h"
#include "message_parser_helpers.h"

#include <boost/date_time/posix_time/posix_time.hpp>

#include <quickfix/Dictionary.h>
#include <quickfix/Session.h>
#include <quickfix/fix44/ExecutionReport.h>
#include <quickfix/fix44/MarketDataIncrementalRefresh.h>
#include <quickfix/fix44/MarketDataRequest.h>
#include <quickfix/fix44/MarketDataRequestReject.h>
#include <quickfix/fix44/MarketDataSnapshotFullRefresh.h>
#include <quickfix/fix44/OrderCancelReject.h>
#include <quickfix/fix44/OrderMassCancelReport.h>
#include <quickfix/fix44/PositionReport.h>
#include <quickfix/fix44/SecurityList.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <chrono>
#include <ctime>
#include <iostream>
#include <quickfix/MySQLConnection.h>

namespace FIX {

void persist(FIX44::SecurityList const &);
//void persist(FIX44::MarketDataSnapshotFullRefresh const &);

// Generic case
template <typename T>
void persistUpdate(T const &);

using encoding_t = unsigned char const *;

quickfix::~quickfix() {
  if (m_initiator != nullptr) {
    m_initiator->stop();
    delete m_initiator;
  }

  m_quickfix_settings.reset();
  m_quickfix_synch.reset();
  m_quickfix_store_factory.reset();
  m_quickfix_log_factory.reset();
}

quickfix::quickfix(config_file_t &configuration, quickfix_user &user)
    : m_session_id(),
      m_user(user),
      m_request_identifier(0),
      m_order_identifier(0),
      m_configuration(configuration),
      m_initiator(nullptr),
      m_quickfix_settings(),
      m_quickfix_synch(),
      m_quickfix_store_factory(),
      m_quickfix_log_factory(),
      m_log_replay() {
  // Initializing quickfix engine
  m_quickfix_settings = std::make_unique<FIX::SessionSettings>(
      m_configuration["FIXConfigurationFile"]);
  m_quickfix_synch = std::make_unique<FIX::SynchronizedApplication>(*this);
  m_quickfix_store_factory =
//          std::make_unique<FIX::MySQLStoreFactory>(*m_quickfix_settings);
      std::make_unique<FIX::FileStoreFactory>(*m_quickfix_settings);
  m_quickfix_log_factory =
//      std::make_unique<FIX::MySQLLogFactory>(*m_quickfix_settings);
      std::make_unique<FIX::FileLogFactory>(*m_quickfix_settings);

  // Indicate if it will be used for log replay or for real
  m_log_replay = m_configuration.find("LogToReplay") != m_configuration.end();
}

bool quickfix::run() {
  if (!m_log_replay) {
    try {
      m_initiator = new FIX::SocketInitiator(
          *m_quickfix_synch, *m_quickfix_store_factory, *m_quickfix_settings,
          *m_quickfix_log_factory);

      m_initiator->start();

    } catch (std::exception const &exception) {
      std::cout << exception.what() << std::endl;
      delete m_initiator;
      return false;
    }
  } else {
    if (m_configuration.find("LogToReplay") == m_configuration.end()) {
      return false;
    }

    auto const configuration = m_quickfix_settings->get();

    std::set<SessionID> sessions = m_quickfix_settings->getSessions();
    if (sessions.empty()) {
      return false;
    }

    auto const &session = *sessions.begin();
    auto const dictionary_path =
        m_quickfix_settings->get(session).getString(FIX::DATA_DICTIONARY);
    auto const receiver =
        m_quickfix_settings->get(session).getString(FIX::TARGETCOMPID);

    quickfix_log_replayer replayer(*this, m_configuration["LogToReplay"],
                                   DataDictionary(dictionary_path), session,
                                   receiver);
    replayer.start();
    return false;
  }
  return true;
}

void quickfix::stop() {
  if (m_initiator) {
    m_initiator->stop();
  }
}

void quickfix::onCreate(SessionID const &session_id) {
  m_session_id = session_id;
}

void quickfix::onLogon(SessionID const & /*session_id*/) { m_user.on_logon(); }

void quickfix::onLogout(SessionID const & /*session_id*/) {
  m_user.on_logout();
}

void quickfix::toAdmin(Message &message, SessionID const & /*session_id*/) {
  auto const &msg_type = message.getHeader().getField(FIX::FIELD::MsgType);

  // Create logon message
  if (msg_type == FIX::MsgType_Logon) {
    create_logon_message(message);
  }
}

void quickfix::toApp(Message & /*message*/,
                     SessionID const & /*session_id*/) throw(DoNotSend) {}

void quickfix::fromAdmin(
    Message const & /*message*/,
    SessionID const & /*session_id*/) throw(FieldNotFound, IncorrectDataFormat,
                                            IncorrectTagValue, RejectLogon) {}

void quickfix::fromApp(
    Message const &message,
    SessionID const &session_id) throw(FieldNotFound, IncorrectDataFormat,
                                       IncorrectTagValue,
                                       UnsupportedMessageType) {
    const std::string & msgTypeValue
            = message.getHeader().getField( FIX::FIELD::MsgType );

    crack(message, session_id);
}

void quickfix::test_request() {
  Message message;
  auto const request_id = std::to_string(m_request_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_TestRequest));

  message.setField(FIX::TestReqID(request_id));

  send_message(message, m_session_id);
}

void quickfix::request_instrument_list() {
  Message message;
  auto const request_id = std::to_string(m_request_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_SecurityListRequest));

  message.setField(FIX::FIELD::SecurityReqID, request_id);
  message.setField(FIX::FIELD::SecurityListRequestType, "0");

  send_message(message, m_session_id);
}

void quickfix::request_positions() {
  Message message;
  auto const request_id = std::to_string(m_request_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_RequestForPositions));

  message.setField(FIX::PosReqID(request_id));
  message.setField(FIX::PosReqType(FIX::PosReqType_POSITIONS));
  message.setField(FIX::SubscriptionRequestType('0'));

  send_message(message, m_session_id);
}

void quickfix::request_mass_status() {
  Message message;
  auto const order_id = std::to_string(m_order_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_OrderMassStatusRequest));

  message.setField(FIX::MassStatusReqID(order_id));
  message.setField(FIX::MassStatusReqType(7));

  send_message(message, m_session_id);
}

void quickfix::request_market_data(string const &symbol) {
  Message message;
  auto const request_id = std::to_string(m_request_identifier++);

  auto &header = message.getHeader();
  header.setField(FIX::MsgType(FIX::MsgType_MarketDataRequest));

  message.setField(FIX::Symbol(symbol));
  message.setField(FIX::MDReqID(request_id));
  message.setField(FIX::SubscriptionRequestType(
      FIX::SubscriptionRequestType_SNAPSHOT_AND_UPDATES));

  message.setField(FIX::MarketDepth(1));
  message.setField(FIX::MDUpdateType(0));

  /** Groups for requesting bid and ask */
  message.setField(FIX::NoMDEntryTypes(1));
  FIX44::MarketDataRequest::NoMDEntryTypes entry_types;
//  entry_types.set(FIX::MDEntryType_BID);
//  message.addGroup(entry_types);
//  entry_types.set(FIX::MDEntryType_OFFER);
//  message.addGroup(entry_types);
    entry_types.set(FIX::MDEntryType_TRADE);
    message.addGroup(entry_types);

  send_message(message, m_session_id);
}

void quickfix::request_trade_data(string const &symbol) {
    Message message;
    auto const request_id = std::to_string(m_request_identifier++);

    auto &header = message.getHeader();
    header.setField(FIX::MsgType(FIX::MsgType_TradeCaptureReportRequest));

    message.setField(FIX::TradeRequestID(request_id));
    message.setField(FIX::TradeRequestType(0));
    message.setField(FIX::Symbol(symbol));
    message.setField(FIX::SubscriptionRequestType(FIX::SubscriptionRequestType_SNAPSHOT_AND_UPDATES));

    send_message(message, m_session_id);
}

string quickfix::send_ioc_order(string const &symbol, side_t order_side,
                                price_t order_price, volume_t order_volume) {
  auto const side = order_side == side_t::BUY ? FIX::Side_BUY : FIX::Side_SELL;

  Message message;
  auto const order_id = std::to_string(m_order_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_NewOrderSingle));

  message.setField(FIX::ClOrdID(order_id));
  message.setField(FIX::Side(side));
  message.setField(FIX::OrderQty(order_volume));
  message.setField(FIX::Price(order_price));
  message.setField(FIX::Symbol(symbol));
  message.setField(FIX::OrdType(FIX::OrdType_LIMIT));
  message.setField(FIX::TimeInForce(FIX::TimeInForce_IMMEDIATE_OR_CANCEL));

  send_message(message, m_session_id);

  return order_id;
}

string quickfix::send_gtc_order(string const &symbol, side_t order_side,
                                price_t order_price, volume_t order_volume) {
  auto const side = order_side == side_t::BUY ? FIX::Side_BUY : FIX::Side_SELL;

  Message message;
  auto const order_id = std::to_string(m_order_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_NewOrderSingle));

  message.setField(FIX::ClOrdID(order_id));
  message.setField(FIX::Side(side));
  message.setField(FIX::OrderQty(order_volume));
  message.setField(FIX::Price(order_price));
  message.setField(FIX::Symbol(symbol));
  message.setField(FIX::OrdType(FIX::OrdType_LIMIT));
  message.setField(FIX::TimeInForce(FIX::TimeInForce_GOOD_TILL_CANCEL));

  send_message(message, m_session_id);

  return order_id;
}

void quickfix::send_cancel_order(std::string const &order_to_cancel) {
  Message message;
  auto const order_id = std::to_string(m_order_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_OrderCancelRequest));

  message.setField(FIX::ClOrdID(order_id));
  message.setField(FIX::OrigClOrdID(order_to_cancel));

  send_message(message, m_session_id);
}

// TODO: To be refined from here on

void quickfix::send_single_order(string const &symbol) {
  static double offset = 0.0;

  auto const side = FIX::Side_SELL;

  Message message;
  auto const order_id = std::to_string(m_order_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_NewOrderSingle));

  message.setField(FIX::ClOrdID(order_id));
  message.setField(FIX::Side(side));
  message.setField(FIX::OrderQty(0.1));
  message.setField(FIX::Price(0.0020 + offset));
  message.setField(FIX::Symbol(symbol));
  // message.setField(FIX::ExecInst(6));
  message.setField(FIX::OrdType(FIX::OrdType_LIMIT));
  message.setField(FIX::TimeInForce(FIX::TimeInForce_GOOD_TILL_CANCEL));
  message.setField(FIX::DeribitLabel("Test_order"));

  send_message(message, m_session_id);
  offset -= 0.0001;
}

void quickfix::send_mass_cancellation_order() {
  Message message;
  auto const order_id = std::to_string(m_order_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_OrderMassCancelRequest));

  message.setField(FIX::ClOrdID(order_id));
  message.setField(
      FIX::MassCancelRequestType(FIX::MassCancelRequestType_CANCEL_ALL_ORDERS));
  message.setField(FIX::TransactTime());

  send_message(message, m_session_id);
}

void quickfix::user_request() {
  Message message;
  auto const order_id = std::to_string(m_order_identifier++);

  auto &header = message.getHeader();

  header.setField(FIX::MsgType(FIX::MsgType_UserRequest));

  message.setField(FIX::UserRequestID(order_id));
  message.setField(FIX::UserRequestType(
      FIX::UserRequestType_REQUEST_INDIVIDUAL_USER_STATUS));
  message.setField(FIX::Username(m_configuration["AccessKey"]));
  send_message(message, m_session_id);
}

void quickfix::create_logon_message(Message &message) {
  // Create timestamp
  unsigned long long timestamp =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  // Creating the random nonce (32 random bytes encoded in base64)
  constexpr int nonce_to_encode_size = 32;
  unsigned char nonce_to_encode[nonce_to_encode_size];
  if (!RAND_bytes(nonce_to_encode, nonce_to_encode_size)) {
    throw(std::runtime_error("Impossible to create random data to login"));
  }

  encoding_t nonce = reinterpret_cast<encoding_t>(nonce_to_encode);
  string nonce64 = ::Deribit::base64_encode(nonce, nonce_to_encode_size);

  // Creating raw data with format timestamp.nonce64
  std::stringstream raw_data_stream;
  raw_data_stream << timestamp << "." << nonce64;
  string raw_data = raw_data_stream.str();

  // Creating password: base64(sha(raw_data+SECRET_KEY))
  string raw_and_secret = raw_data + m_configuration["AccessSecret"];
  unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, raw_and_secret.c_str(), raw_and_secret.size());
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);

//  SHA256_CTX sha256;
//  SHA256_Init(&sha256);
//  SHA256_Update(&sha256, raw_and_secret.c_str(), raw_and_secret.size());
//  SHA256_Final(hash, &sha256);
  string password = ::Deribit::base64_encode(hash, SHA256_DIGEST_LENGTH);

  // Setting message fields
  message.setField(FIX::FIELD::Username, m_configuration["AccessKey"]);
  message.setField(FIX::FIELD::Password, password);
  message.setField(FIX::FIELD::RawData, raw_data);
  message.setField(FIX::FIELD::ResetSeqNumFlag, "N");
}

void quickfix::onMessage(FIX44::PositionReport const &message,
                         SessionID const &session_id) {
  // Total positions reported and vector's initialization
  auto const position_size = field<size_t>::get(message, FIELD::NoPositions);

  // Getting all elements inside the group
  optional<positions_list_t> positions =
      position_size ? positions_list_t{}
                    : optional<positions_list_t>(boost::none);
  FIX44::PositionReport::NoPositions position_group;
  for (size_t i = 1; i <= position_size; ++i) {
    message.getGroup(i, position_group);

    auto quantity_long = field<volume_t>::get(position_group, FIELD::LongQty);
    auto quantity_short = field<volume_t>::get(position_group, FIELD::ShortQty);
    auto quantity =
        double_equals(quantity_long, 0) ? quantity_short : quantity_long;

    // If quantity is 0, ignore the position
    if (quantity == 0) {
      continue;
    }

    // clang-format off
    position_t position = {
		field<string>::get(position_group, FIELD::Symbol),
		quantity,
		field<side_t>::get(position_group, FIELD::Side),
		field<price_t>::get(position_group, FIELD::SettlPrice),
		field<price_t>::get(position_group, FIELD::UnderlyingEndPrice)};
    // clang-format on
    positions->push_back(std::move(position));
  }

  // Communicate to the user
  m_user.on_message(positions);
}

void quickfix::onMessage(FIX44::SecurityList const &message,
                         SessionID const &session_id) {

  // Total instruments reported and vector's initialization
  auto const instruments_size =
      field<size_t>::get(message, FIELD::NoRelatedSym);

  // Getting all elements inside the group
  FIX44::SecurityList::NoRelatedSym instruments_group;
  optional<instruments_list_t> instruments =
      instruments_size ? instruments_list_t{}
                       : optional<instruments_list_t>(boost::none);
  for (size_t i = 1; i <= instruments_size; ++i) {
    message.getGroup(i, instruments_group);

    instrument_t instrument = {
        field<string>::get(instruments_group, FIELD::Symbol),
        field<string>::get(instruments_group, FIELD::SecurityDesc),
        field<string>::get(instruments_group, FIELD::SecurityType),
        field<currency>::get(instruments_group, FIELD::Currency),
        field<optional<double>>::get(instruments_group,
                                     FIELD::ContractMultiplier),
        field<optional<option_type_t>>::get(instruments_group,
                                            FIELD::PutOrCall),
        field<optional<price_t>>::get(instruments_group, FIELD::StrikePrice),
        field<optional<currency>>::get(instruments_group,
                                       FIELD::StrikeCurrency),
        field<optional<ptime>>::get(instruments_group, FIELD::MaturityDate),
        field<optional<volume_t>>::get(instruments_group, FIELD::MinTradeVol),
        field<optional<double>>::get(instruments_group,
                                     FIELD::MinPriceIncrement),
    };

    std::cout << "onMessage(FIX44::SecurityList): " << instrument << std::endl;

    instruments->push_back(std::move(instrument));
  }

  persist(message);

  // Communicate to the user
  m_user.on_message(instruments);
}

void quickfix::onMessage(FIX44::MarketDataRequestReject const &message,
                         SessionID const &session_id) {
  auto const failure_text = field<string>::get(message, FIELD::Text);

  // Communicate to the user
  m_user.on_message(failure_text);
}

void quickfix::onMessage(FIX44::MarketDataSnapshotFullRefresh const &message,
                         SessionID const &session_id) {
      market_update_t update;

  // Populate the update with the update components
  auto const symbol = field<string>::get(message, FIELD::Symbol);
  update.symbol = symbol;
  update.contract_multiplier =
      field<optional<double>>::get(message, FIELD::ContractMultiplier);
  update.underlying_symbol =
      field<optional<string>>::get(message, FIELD::UnderlyingSymbol);
  update.underlying_mid_price =
      field<optional<price_t>>::get(message, FIELD::UnderlyingPx);

  // Fill market update vector
  auto const level_depth = field<size_t>::get(message, FIELD::NoMDEntries);
  FIX44::MarketDataSnapshotFullRefresh::NoMDEntries entries_group;

  if (level_depth > 0) {
    update.updates.resize(level_depth);

    for (size_t index = 0; index < level_depth; ++index) {
      FIX::Group group = message.getGroup(index + 1, entries_group);

      update.updates[index].type =
          field<market_type_t>::get(group, FIELD::MDEntryType);

      update.updates[index].update_type = market_update_action_t::NEW;
        update.updates[index].side =
                field<side_t>::get(group, FIELD::Side);
        update.updates[index].level_price =
                field<price_t>::get(group, FIELD::MDEntryPx);
      update.updates[index].level_volume =
          field<volume_t>::get(group, FIELD::MDEntrySize);
        update.updates[index].entryDate =
                field<optional<ptime>>::get(group, FIELD::MDEntryDate);

    }
  }

  // Communicate to the user
  m_user.on_message(update);

  persistUpdate(message);

  std::cout << "(W): " << update << std::endl;
}

void quickfix::onMessage(FIX44::MarketDataIncrementalRefresh const &message,
                         SessionID const &session_id) {
  market_update_t update;

  // Populate the update with the update components
  auto const symbol = field<string>::get(message, FIELD::Symbol);
  update.symbol = symbol;

  // Fill market update vector
  auto const level_depth = field<size_t>::get(message, FIELD::NoMDEntries);
  FIX44::MarketDataIncrementalRefresh::NoMDEntries entries_group;

  if (level_depth > 0) {
    update.updates.resize(level_depth);

    for (size_t index = 0; index < level_depth; ++index) {
      message.getGroup(index + 1, entries_group);

      update.updates[index].type =
          field<market_type_t>::get(entries_group, FIELD::MDEntryType);

      update.updates[index].update_type = field<market_update_action_t>::get(
          entries_group, FIELD::MDUpdateAction);
      ;
        update.updates[index].side =
                field<side_t>::get(entries_group, FIELD::Side);
      update.updates[index].level_price =
          field<price_t>::get(entries_group, FIELD::MDEntryPx);
      update.updates[index].level_volume =
          field<volume_t>::get(entries_group, FIELD::MDEntrySize);
        update.updates[index].entryDate =
                field<optional<ptime>>::get(entries_group, FIELD::MDEntryDate);
    }
  }

  // Communicate to the user
  m_user.on_message(update);

  persistUpdate(message);

    std::cout << "(X): " << update << std::endl;
}

void quickfix::onMessage(FIX44::ExecutionReport const &message,
                         SessionID const &session_id) {
  execution_report_t report;

  report.order_id = field<optional<string>>::get(message, FIELD::ClOrdID);
  report.original_order_id =
      field<optional<string>>::get(message, FIELD::OrigClOrdID);
  report.order_status =
      field<optional<order_status_t>>::get(message, FIELD::OrdStatus);
  report.side = field<optional<side_t>>::get(message, FIELD::Side);
  report.transaction_time =
      field<optional<ptime>>::get(message, FIELD::TransactTime);
  report.open_volume =
      field<optional<volume_t>>::get(message, FIELD::LeavesQty);
  report.executed_volume =
      field<optional<volume_t>>::get(message, FIELD::CumQty);
  report.order_volume =
      field<optional<volume_t>>::get(message, FIELD::OrderQty);
  report.order_type =
      field<optional<order_type_t>>::get(message, FIELD::OrdType);
  report.reject_reason =
      field<optional<int>>::get(message, FIELD::OrdRejReason);
  report.symbol = field<optional<string>>::get(message, FIELD::Symbol);

  report.order_price = field<optional<price_t>>::get(message, FIELD::Price);
  report.volume_type =
      field<optional<volume_type_t>>::get(message, FIELD::QtyType);
  report.contract_multiplier =
      field<optional<double>>::get(message, FIELD::ContractMultiplier);
  report.average_execution_price =
      field<optional<price_t>>::get(message, FIELD::AvgPx);
  report.maximun_show_volume =
      field<optional<volume_t>>::get(message, FIELD::MaxShow);
  report.implied_volatility =
      field<optional<double>>::get(message, FIELD::Volatility);
  report.pegged_price =
      field<optional<price_t>>::get(message, FIELD::PeggedPrice);

  report.mass_status_request_type =
      field<optional<int>>::get(message, FIELD::MassStatusReqType);
  report.mass_status_report_number =
      field<optional<int>>::get(message, FIELD::TotNumReports);

  // Communicate to the user
  if (report.mass_status_request_type &&
      (report.mass_status_request_type.get() == 7)) {
    m_user.on_mass_status_report(report.mass_status_report_number.get());
  } else {
    m_user.on_message(report);
  }
}

void quickfix::onMessage(FIX44::OrderCancelReject const &message,
                         SessionID const &session_id) {
  order_cancel_reject_t report{
      field<string>::get(message, FIELD::ClOrdID),
      field<string>::get(message, FIELD::OrigClOrdID),
      field<optional<order_status_t>>::get(message, FIELD::OrdStatus),
      field<optional<string>>::get(message, FIELD::Text)};

  // Communicate to the user
  m_user.on_message(report);
}

void quickfix::onMessage(FIX44::OrderMassCancelReport const &message,
                         SessionID const &session_id) {
  mass_cancel_report_t report{
      field<string>::get(message, FIELD::ClOrdID),
      field<mass_cancelation_type_t>::get(message,
                                          FIELD::MassCancelRequestType),
      (field<mass_cancelation_type_t>::get(
           message, FIELD::MassCancelResponse) == report.type),
      field<optional<mass_cancelation_error_t>>::get(
          message, FIELD::MassCancelRejectReason)};

  // Communicate to the user
  m_user.on_message(report);
}

void quickfix::send_message(Message &message, SessionID const &session) {
  if (!m_log_replay) {
    FIX::Session::sendToTarget(message, m_session_id);
  }
}

MySQLConnection* pConnection = new MySQLConnection( "crypto", "root", "", "localhost", 3306 );

void persist(FIX44::SecurityList const &messages) {

    std::stringstream queryString;
    queryString << "INSERT INTO instruments "
                << "(Symbol, SecurityDesc, SecurityType, PutOrCall, StrikePrice, StrikeCurrency, Currency, PriceQuoteCurrency, "
                   "InstrumentPricePrecision, MinPriceIncrement, UnderlyingSymbol, IssueDate, MaturityDate, MaturityTime, "
                   "MinTradeVol, SettlType, SettlCurrency, CommCurrency, ContractMultiplier, SecurityStatus)"
                << " VALUES ";

    FIX44::SecurityList::NoRelatedSym group;
    FIX::NoRelatedSym noSym;

    for (int i = 0; i < messages.get(noSym); i++) {
        messages.getGroup(i + 1, group);
        queryString << "('" << field<string>::get(group, FIELD::Symbol) << "', "
                    << "'" << field<string>::get(group, FIELD::SecurityDesc) << "', "
                    << "'" << field<string>::get(group, FIELD::SecurityType) << "', "
                    << to_string(field<optional<int>>::get(group, FIELD::PutOrCall)) << ", "
                    << to_string(field<optional<price_t>>::get(group, FIELD::StrikePrice)) << ", "
                    << (group.isSetField(FIELD::StrikeCurrency) ? "'" + field<string>::get(group, FIELD::StrikeCurrency) + "'" : "NULL") <<  ", "
                    << "'" << field<string>::get(group, FIELD::Currency) << "', "
                    << "'" << field<string>::get(group, FIELD::PriceQuoteCurrency) << "', "
                    << field<int>::get(group, FIELD::InstrumentPricePrecision) << ", "
                    << field<price_t>::get(group, FIELD::MinPriceIncrement) << ", "
                    << "'" << field<string>::get(group, FIELD::UnderlyingSymbol) << "', "
                    << "'" << to_string(field<optional<ptime>>::get(group, FIELD::IssueDate)) << "', "
                    << "'" << to_string(field<optional<ptime>>::get(group, FIELD::MaturityDate)) << "', "
                    << "'" << to_string(field<optional<ptime>>::get(group, FIELD::MaturityTime)) << "', "
                    << (group.isSetField(FIELD::MinTradeVol) ? field<volume_t>::get(group, FIELD::MinTradeVol) : NULL) << ", "
                    << (group.isSetField(FIELD::SettlType) ? "'" + to_string(field<string>::get(group, FIELD::SettlType)) +  "'" : "NULL") << ", "
                    << (group.isSetField(FIELD::SettlCurrency) ? "'" + to_string(field<string>::get(group, FIELD::SettlCurrency)) + "'" : "NULL") << ", "
                    << (group.isSetField(FIELD::CommCurrency) ? "'" + to_string(field<string>::get(group, FIELD::CommCurrency)) + "'" : "NULL") << ", "
                    << (group.isSetField(FIELD::ContractMultiplier) ? field<optional<double>>::get(group, FIELD::ContractMultiplier) : NULL) << ", "
                    << (group.isSetField(FIELD::SecurityStatus) ? "'" + field<string>::get(group, FIELD::SecurityStatus) + "'" : "NULL")
                    << ((i == messages.get(noSym) - 1) ? ")" : "), ")
                    ;
    }

//    std::cout << queryString.str() << std::endl;

    FIX::MySQLQuery query( queryString.str() );
    pConnection->execute(query);
}

template <typename T>
void persistUpdate(T const &messages) {

    std::stringstream queryString;
    queryString << "INSERT INTO market_trades "
                << "(Symbol, MDReqID, UnderlyingSymbol, UnderlyingPx, ContractMultiplier, PutOrCall, TradeVolume24h, "
                << "MarkPrice, OpenInterest, CurrentFunding, Funding8h, MDEntryType, MDUpdateAction, MDEntryPx, MDEntrySize, "
                << "MDEntryDate, DeribitTradeId, Side, Price, Text, OrderID, SecondaryOrderID, OrdStatus, DeribitLabel, "
                << "DeribitLiquidation, TrdMatchID)"
                << " VALUES ";

    auto const level_depth = field<size_t>::get(messages, FIELD::NoMDEntries);
    typename T::NoMDEntries group;

    bool go = false;

    for (int i = 0; i < level_depth; i++) {
        messages.getGroup(i + 1, group);
        if (*field<optional<market_type_t>>::get(group, FIELD::MDEntryType) != market_type_t::TRADE) continue;
        go = true;
        queryString << "('" << field<string>::get(messages, FIELD::Symbol) << "', "
                    << (messages.isSetField(FIELD::MDReqID) ? "'" + to_string(field<string>::get(messages, FIELD::MDReqID)) +  "'" : "NULL") << ", "
                    << (messages.isSetField(FIELD::UnderlyingSymbol) ? "'" + to_string(field<string>::get(messages, FIELD::UnderlyingSymbol)) +  "'" : "NULL") << ", "
                    << (messages.isSetField(FIELD::UnderlyingPx) ? to_string(field<price_t>::get(messages, FIELD::UnderlyingPx)) : "NULL") << ", "
                    << (messages.isSetField(FIELD::ContractMultiplier) ? to_string(field<price_t>::get(messages, FIELD::ContractMultiplier)) : "NULL") << ", "
                    << to_string(field<optional<int>>::get(messages, FIELD::PutOrCall)) << ", "
                    << (messages.isSetField(FIX::TradeVolume24h::tag) ? to_string(field<price_t>::get(messages, FIX::TradeVolume24h::tag)) : "NULL") << ", "
                    << (messages.isSetField(DeribitMarkPrice::tag) ? to_string(field<price_t>::get(messages,DeribitMarkPrice::tag)) : "NULL") << ", "
                    << (messages.isSetField(FIELD::OpenInterest) ? to_string(field<price_t>::get(messages, FIELD::OpenInterest)) : "NULL") << ", "
                    << (messages.isSetField(CurrentFunding::tag) ? to_string(field<price_t>::get(messages,CurrentFunding::tag)) : "NULL") << ", "
                    << (messages.isSetField(Funding8h::tag) ? to_string(field<price_t>::get(messages,Funding8h::tag)) : "NULL") << ", "

                    << to_string(field<optional<int>>::get(group, FIELD::MDEntryType)) << ", "
                    << to_string(field<optional<int>>::get(group, FIELD::MDUpdateAction)) << ", "
                    << to_string(field<optional<price_t>>::get(group, FIELD::MDEntryPx)) << ", "
                    << to_string(field<optional<volume_t>>::get(group, FIELD::MDEntrySize)) << ", "
                    << "'" << to_string(field<optional<ptime>>::get(group, FIELD::MDEntryDate)) << "', "
                    << (group.isSetField(DeribitTradeId::tag) ? "'" + field<string>::get(group, DeribitTradeId::tag) + "'" : "NULL") <<  ", "
                    << (group.isSetField(FIELD::Side) ? "'" + to_string(field<string>::get(group, FIELD::Side)) +  "'" : "NULL") << ", "
                    << to_string(field<price_t>::get(group, FIELD::Price)) << ", "
                    << "'" << field<string>::get(group, FIELD::Text) << "', "
                    << "'" << field<string>::get(group, FIELD::OrderID) << "', "
                    << "'" << field<string>::get(group, FIELD::SecondaryOrderID) << "', "
                    << (group.isSetField(FIELD::OrdStatus) ? "'" + to_string(field<string>::get(group, FIELD::OrdStatus)) + "'" : "NULL") << ", "
                    << (group.isSetField(DeribitLabel::tag) ? "'" + to_string(field<string>::get(group, DeribitLabel::tag)) + "'" : "NULL") << ", "
                    << (group.isSetField(DeribitLiquidation::tag) ? "'" + field<string>::get(group, DeribitLiquidation::tag) + "'" : "NULL") << ", "
                    << (group.isSetField(FIELD::TrdMatchID) ? "'" + field<string>::get(group, FIELD::TrdMatchID) + "'" : "NULL")
                    << ((i == level_depth - 1) ? ")" : "), ")
                ;
    }

    if (!go) return;
//    std::cout << queryString.str() << std::endl;

    FIX::MySQLQuery query( queryString.str() );
    pConnection->execute(query);
}

}  // namespace FIX
