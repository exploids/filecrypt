/**
 * @author Luca Selinski
 */
module com.exploids.filecrypt {
    requires info.picocli;
    requires org.bouncycastle.provider;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.yaml;
    requires org.apache.commons.io;
    requires org.apache.commons.compress;
    exports com.exploids.filecrypt to com.fasterxml.jackson.databind;
    opens com.exploids.filecrypt to info.picocli;
    exports com.exploids.fancyprinter to com.fasterxml.jackson.databind;
    opens com.exploids.fancyprinter to info.picocli;
}
