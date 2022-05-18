package com.exploids.filecrypt;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;

public class SpacedNamingStrategy extends PropertyNamingStrategies.SnakeCaseStrategy {
    @Override
    public String translate(String input) {
        return super.translate(input).replace('_', ' ');
    }
}
