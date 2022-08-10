package com.exploids.filecrypt.serialization;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;

/**
 * A naming strategy that translates to lowercase names separated by spaces.
 *
 * @author Luca Selinski
 */
public class SpacedNamingStrategy extends PropertyNamingStrategies.SnakeCaseStrategy {
    /**
     * Translates a name.
     *
     * @param input the source name
     * @return the translated name
     */
    @Override
    public String translate(String input) {
        return super.translate(input).replace('_', ' ');
    }
}
