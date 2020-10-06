import java.math.BigInteger;
import java.util.List;

public class SHSParamters {

    protected List<BigInteger> param;

    public SHSParamters(List<BigInteger> param) {
        this.param = param;
    }

    public List<BigInteger> getParams() {
        return param;
    }

    public void setParams(List<BigInteger> key) {
        this.param = key;
    }
}
