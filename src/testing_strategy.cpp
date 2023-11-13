#include "testing_strategy.h"
#include <quickfix/MySQLConnection.h>
void persist(optional<instruments_list_t> const&);

std::string TEST_OPTION = "BTC-27OCT23-28000-C";

optional<instruments_list_t> instruments;

testing_strategy::testing_strategy(config_file_t &configuration)
    : m_configuration(configuration),
      m_market(std::make_unique<FIX::quickfix>(m_configuration, *this)) {}

testing_strategy::~testing_strategy() {
  if (m_market) {
    m_market->stop();
  }
}

bool testing_strategy::run() {
  std::cout << "Running strategy..." << std::endl;
  if (!m_market->run()) {
    std::cerr << "ERROR: Impossible to initialize the market" << std::endl;
    return false;
  }

  int choice;
  std::stringstream menu;
  menu << "###########################################" << std::endl;
  menu << "# Menu:                                   #" << std::endl;
  menu << "#     1 - Test request                    #" << std::endl;
  menu << "#     2 - Request instrument list         #" << std::endl;
  menu << "#     3 - Request market data             #" << std::endl;
  menu << "#     4 - Send single order to the market #" << std::endl;
  menu << "#     5 - Cancel order                    #" << std::endl;
  menu << "#     6 - Mass cancelation order          #" << std::endl;
  menu << "#     7 - User request                    #" << std::endl;
  menu << "#     8 - Mass status request             #" << std::endl;
  menu << "#     10 - Request positions list         #" << std::endl;
  menu << "#     11 - Request trade captures         #" << std::endl;
  menu << "#     12 - BTC-PERP/ETH-PERP market data  #" << std::endl;
  menu << "#-----------------------------------------#" << std::endl;
  menu << "#     0 - Quit                            #" << std::endl;
  menu << "###########################################" << std::endl;

  std::cout << menu.str() << std::endl;
  std::cin >> choice;

  while (choice != 0) {
    switch (choice) {
      case 1: {
        m_market->test_request();
        break;
      }
      case 2: {
        m_market->request_instrument_list();
        break;
      }
      case 3: {
          if (!instruments) {
              m_market->request_trade_data(TEST_OPTION);
          } else {
              boost::gregorian::date dateToCompare(2023, 10, 27);

              for (const instrument_t& instrument : *instruments) {

                  if (instrument.maturity_date && instrument.maturity_date->date() != dateToCompare) continue;
                  if (instrument.strike_price && *(instrument.strike_price) > 30000) continue;
                  if ((to_string(instrument.main_currency) != "BTC")) continue;
                  if (instrument.type == "INDEX" ) continue;

                  m_market->request_market_data(instrument.symbol);
              }
          }
        m_market->request_market_data(TEST_OPTION);
        break;
      }
      case 4: {
        m_market->send_single_order(TEST_OPTION);
        break;
      }
      case 5: {
        std::string order_to_cancel;
        std::cout << "Which order ID: ";
        std::cin >> order_to_cancel;
        m_market->send_cancel_order(order_to_cancel);
        break;
      }
      case 6: {
        m_market->send_mass_cancellation_order();
        break;
      }
      case 7: {
        m_market->user_request();
        break;
      }
      case 8: {
        m_market->request_mass_status();
        break;
      }
        case 10: {
            m_market->request_positions();
            break;
        }
        case 11: {
            if (!instruments) {
//                m_market->request_trade_data(TEST_OPTION);
                m_market->request_trade_data("BTC-PERPETUAL");
                m_market->request_trade_data("ETH-PERPETUAL");
            } else {
                boost::gregorian::date dateToCompare(2023, 10, 27);

                for (const instrument_t& instrument : *instruments) {

                    if (instrument.maturity_date && instrument.maturity_date->date() != dateToCompare) continue;
                    if (instrument.strike_price && *(instrument.strike_price) > 30000) continue;
                    if ((to_string(instrument.main_currency) != "BTC")) continue;
                    if (instrument.type == "INDEX" ) continue;

                    m_market->request_trade_data(instrument.symbol);
                }
            }
            break;
        }
        case 12: {
            m_market->request_market_data("BTC-PERPETUAL");
            m_market->request_market_data("ETH-PERPETUAL");
            break;
        }
      default: {
        std::cout << "Option " << choice << " is not available" << std::endl;
      }
    }
    std::cout << menu.str();
    std::cin >> choice;
  }
  return false;
}

void testing_strategy::on_message(optional<instruments_list_t> const& i) {
    instruments = i;
//    persist(i);
}

void testing_strategy::on_logon() {
    std::cout << "on_logon" << std::endl;
    m_market->request_market_data("BTC-PERPETUAL");
    m_market->request_market_data("ETH-PERPETUAL");
}
