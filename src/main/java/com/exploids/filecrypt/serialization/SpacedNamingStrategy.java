package com.exploids.filecrypt.serialization;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;

public class SpacedNamingStrategy extends PropertyNamingStrategies.SnakeCaseStrategy {
    @Override
    public String translate(String input) {
        return super.translate(input).replace('_', ' ');
    }
}
