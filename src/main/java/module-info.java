/**
 * @author Luca Selinski
 */
module com.exploids.filecrypt {
    requires info.picocli;
    requires org.bouncycastle.provider;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.toml;
    requires org.apache.commons.compress;
    exports com.exploids.filecrypt to com.fasterxml.jackson.databind;
    opens com.exploids.filecrypt to info.picocli;
}
