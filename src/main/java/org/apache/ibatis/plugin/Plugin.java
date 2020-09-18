/**
 *    Copyright 2009-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package org.apache.ibatis.plugin;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.reflection.ExceptionUtil;

/**
 * @author Clinton Begin
 */
public class Plugin implements InvocationHandler {

  private final Object target;
  private final Interceptor interceptor;
  private final Map<Class<?>, Set<Method>> signatureMap;

  private Plugin(Object target, Interceptor interceptor, Map<Class<?>, Set<Method>> signatureMap) {
    this.target = target;
    this.interceptor = interceptor;
    this.signatureMap = signatureMap;
  }

  public static Object wrap(Object target, Interceptor interceptor) {
    // analysis and fetch @Intercepts annotation contents
    Map<Class<?>, Set<Method>> signatureMap = getSignatureMap(interceptor);

    Class<?> type = target.getClass();

    // get all interfaces that target class implement or extends
    Class<?>[] interfaces = getAllInterfaces(type, signatureMap);

    if (interfaces.length > 0) {

      /**
       * The usage of {@link  Proxy#newProxyInstance(ClassLoader, Class[], InvocationHandler)} is to create a Proxy class instance
       * for specific interfaces that dispatches method invocation to the specified invocation handler. {@param classLoader} means
       * the class loader to define the proxy class， here means the Intercept class which could be {@link org.apache.ibatis.executor.Executor}
       * , {@link org.apache.ibatis.executor.parameter.ParameterHandler}, {@link org.apache.ibatis.executor.resultset.ResultSetHandler}，
       * {@link org.apache.ibatis.executor.statement.StatementHandler} classloader.{@param interfaces} means the interface the proxy class
       * implements. {@param handler} means the target invocation handler to dispatch method invocations to
       */
      return Proxy.newProxyInstance(
          type.getClassLoader(),
          interfaces,
          new Plugin(target, interceptor, signatureMap));
    }
    return target;
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    try {
      /**
       * get proxy method from caching map using key {@link Method#getDeclaringClass()} which corresponding to
       * {@link Signature} content {@code type}. Were there exist same value of {@param type} field in
       */
      Set<Method> methods = signatureMap.get(method.getDeclaringClass());
      if (methods != null && methods.contains(method)) {
        return interceptor.intercept(new Invocation(target, method, args));
      }
      return method.invoke(target, args);
    } catch (Exception e) {
      throw ExceptionUtil.unwrapThrowable(e);
    }
  }

  /**
   * Getting informations from {@Code @Intercepts} annotation ahead of the class definition, and return the contents of
   * the {@code @Intercepts} as a map.
   *
   * @param interceptor
   * @return
   */
  private static Map<Class<?>, Set<Method>> getSignatureMap(Interceptor interceptor) {
    /**
     * Getting {@link Intercepts} annotation defined ahead of the customized interceptors. If the annotation is empty, directly
     * throw the {@link PluginException} to tell the user that the interceptors should add {@link Intercepts} annotation on the
     * class signature.
     */
    Intercepts interceptsAnnotation = interceptor.getClass().getAnnotation(Intercepts.class);
    // issue #251
    if (interceptsAnnotation == null) {
      throw new PluginException("No @Intercepts annotation was found in interceptor " + interceptor.getClass().getName());
    }

    /**
     * the following codes shows that the content format of the {@link Intercepts}. There should be 0 or more {@link Signature}
     * in the {@link Intercepts}. There are three fields in {@link Signature} annotation, which are {@code type, method, args}.
     * The field {@code type} is a {@link Class<?>} member, which means target class type we want to intercept. The {@code method}
     * is a {@link String} member, which mean the method name we want to intercept. The {@code args} is a {@link java.lang.Class<?>}
     * array, which means the parameters in the function.
     *
     */
    Signature[] sigs = interceptsAnnotation.value();
    Map<Class<?>, Set<Method>> signatureMap = new HashMap<>();
    for (Signature sig : sigs) {
      Set<Method> methods = signatureMap.computeIfAbsent(sig.type(), k -> new HashSet<>());
      try {
        Method method = sig.type().getMethod(sig.method(), sig.args());
        methods.add(method);
      } catch (NoSuchMethodException e) {
        throw new PluginException("Could not find method on " + sig.type() + " named " + sig.method() + ". Cause: " + e, e);
      }
    }
    return signatureMap;
  }

  /**
   * Judge if the target class {@param type} exists in the {@link Intercepts} annotation config. add the
   *
   * @param type
   * @param signatureMap
   * @return
   */
  private static Class<?>[] getAllInterfaces(Class<?> type, Map<Class<?>, Set<Method>> signatureMap) {
    Set<Class<?>> interfaces = new HashSet<>();
    while (type != null) {
      /**
       * the code {@code type.getInterfaces()} means if the type class is a specify class implements one or more interfaces, method
       * will return all the interfaces the type implement and in correspond implementation order. Were the {@code type} class is an
       * interface, then return all the interfaces that the {@code type} {@link extends} and in declaring order.
       */
      for (Class<?> c : type.getInterfaces()) {
        if (signatureMap.containsKey(c)) {
          interfaces.add(c);
        }
      }
      type = type.getSuperclass();
    }
    return interfaces.toArray(new Class<?>[interfaces.size()]);
  }

}
