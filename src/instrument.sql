USE deribit;

DROP TABLE IF EXISTS instruments;

CREATE TABLE instruments (
                          Symbol VARCHAR(128) NOT NULL,
                          SecurityDesc VARCHAR(128)  NULL,
                          SecurityType VARCHAR(16)  NULL,
                          PutOrCall int  NULL,
                          StrikePrice decimal(14, 6)  NULL,
                          StrikeCurrency varchar(16)  NULL,
                          Currency VARCHAR(16)  NULL,
                          PriceQuoteCurrency VARCHAR(16)  NULL,
                          InstrumentPricePrecision int  NULL,
                          MinPriceIncrement decimal(10,6)  NULL,
                          UnderlyingSymbol varchar(32)  NULL,
                          IssueDate datetime  NULL,
                          MaturityDate date NULL,
                          MaturityTime time NULL,
                          MinTradeVol decimal(10,6)  NULL,
                          SettlType VARCHAR(32)  NULL,
                          SettlCurrency varchar(32) NULL,
                          CommCurrency varchar(32)  NULL,
                          ContractMultiplier decimal(10,4)  NULL,
                          SecurityStatus VARCHAR(10)  NULL,
                          PRIMARY KEY (symbol)
);
