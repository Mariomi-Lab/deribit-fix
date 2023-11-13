//
// Created by George Tang on 2023/10/5.
//

#ifndef DERIBIT_DERIBITMESSAGECRACKER_H
#define DERIBIT_DERIBITMESSAGECRACKER_H

#include <quickfix/MessageCracker.h>

class MyMessageManipulator : public FIX::MessageCracker {
public:
    void onMessage(const FIX::Message& message, const FIX::SessionID& sessionID) override {
        try {
            // Check if the message has MsgType 'y'
            if (message.getHeader().getField(FIX::FIELD::MsgType) == "y") {
                // Add the Currency field to the message
                FIX::Currency currencyField;
                currencyField.setString("USD"); // Set the desired currency value
                message.setField(currencyField);
            }
        } catch (const FIX::FieldNotFound&) {
            // Handle the case where MsgType is not present in the message
        }
    }
};

#endif //DERIBIT_DERIBITMESSAGECRACKER_H
