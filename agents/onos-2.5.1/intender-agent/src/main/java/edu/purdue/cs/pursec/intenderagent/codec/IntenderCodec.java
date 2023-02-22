package edu.purdue.cs.pursec.intenderagent.codec;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;
import org.onosproject.codec.CodecService;
import org.onosproject.net.intent.Constraint;

import java.util.HashMap;
import java.util.Map;

public class IntenderCodec implements CodecContext {
    private final ObjectMapper mapper = new ObjectMapper();

    private final CodecService codecService;
    private final Map<Class<?>, Object> services = new HashMap<>();

    public IntenderCodec(CodecService codecService) {
        this.codecService = codecService;
        codecService.unregisterCodec(Constraint.class);
        codecService.registerCodec(Constraint.class, new MyConstraintCodec());
    }

    @Override
    public ObjectMapper mapper() {
        return mapper;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> JsonCodec<T> codec(Class<T> entityClass) {
        return codecService.getCodec(entityClass);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T getService(Class<T> serviceClass) {
        return (T) services.get(serviceClass);
    }

    public <T> void registerService(Class<T> serviceClass, T impl) {
        services.put(serviceClass, impl);
    }
}
