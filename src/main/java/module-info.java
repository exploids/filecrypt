/**
 * @author Luca Selinski
 */
module com.exploids.filecrypt {
    requires info.picocli;
    requires org.bouncycastle.provider;
    opens com.exploids.filecrypt to info.picocli;
}
