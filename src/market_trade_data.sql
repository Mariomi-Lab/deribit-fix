USE deribit;

DROP TABLE IF EXISTS market_trades;

CREATE TABLE market_trades (
                             Symbol VARCHAR(128) NOT NULL,
                             MDReqID VARCHAR(16)  NULL,
                             UnderlyingSymbol VARCHAR(128)  NULL,
                             UnderlyingPx decimal(14, 6)  NULL,
                             ContractMultiplier decimal(10,4)  NULL,
                             PutOrCall int  NULL,
                             TradeVolume24h decimal(14, 6)  NULL,
                             MarkPrice decimal(14, 6)  NULL,
                             OpenInterest decimal(14, 6)  NULL,
                             CurrentFunding decimal(14, 6)  NULL comment 'only in 35=w' ,
                             Funding8h varchar(16)  NULL comment 'only in 35=w',
                             MDEntryType int NOT NULL,
                             MDUpdateAction varchar(1) NULL comment 'only in 35=x' ,
                             MDEntryPx decimal(14, 6)  NULL,
                             MDEntrySize decimal(14, 6)  NULL,
                             MDEntryDate datetime NULL,
                             DeribitTradeId VARCHAR(64)  NULL,
                             Side varchar(1) NULL,
                             Price decimal(14, 6)  NULL,
                             Text VARCHAR(64)  NULL,
                             OrderID VARCHAR(64)  NULL,
                             SecondaryOrderID VARCHAR(64)  NULL,
                             OrdStatus varchar(1) NULL,
                             DeribitLabel VARCHAR(64)  NULL,
                             DeribitLiquidation VARCHAR(16)  NULL,
                             TrdMatchID VARCHAR(64)  NULL
);
