/**
 * @author Luca Selinski
 */
module com.exploids.filecrypt {
    requires org.slf4j;
    requires info.picocli;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.util;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.yaml;
    requires org.apache.commons.io;
    requires org.apache.commons.compress;
    exports com.exploids.filecrypt to com.fasterxml.jackson.databind;
    opens com.exploids.filecrypt to info.picocli;
    exports com.exploids.fancyprinter to com.fasterxml.jackson.databind;
    opens com.exploids.fancyprinter to info.picocli;
    exports com.exploids.filecrypt.serialization to com.fasterxml.jackson.databind;
    opens com.exploids.filecrypt.serialization to info.picocli;
    exports com.exploids.filecrypt.model to com.fasterxml.jackson.databind;
    opens com.exploids.filecrypt.model to info.picocli;
    exports com.exploids.filecrypt.utility to com.fasterxml.jackson.databind;
    opens com.exploids.filecrypt.utility to info.picocli;
}
