package edu.purdue.cs.pursec.ifuzzer.fuzz.api;

import org.objectweb.asm.Type;

import static java.util.Objects.hash;


public class JavaNames {

    public static int getHash(Object key, int max) {
        int hashId = hash(key) % (max - 1);
        if (hashId < 0)
            hashId += max - 1;

        return hashId + 1;
    }

    public static String getPackageName(final String vmname) {
        if (vmname.length() == 0) {
            return "default";
        }
        return vmname.replace('/', '.');
    }

    private static String getClassName(final String vmname) {
        final int pos = vmname.lastIndexOf('/');
        final String name = pos == -1 ? vmname : vmname.substring(pos + 1);
        return name.replace('$', '.');
    }

    private static boolean isAnonymous(final String vmname) {
        final int dollarPosition = vmname.lastIndexOf('$');
        if (dollarPosition == -1) {
            return false;
        }
        final int internalPosition = dollarPosition + 1;
        if (internalPosition == vmname.length()) {
            // shouldn't happen for classes compiled from Java source
            return false;
        }
        // assume non-identifier start character for anonymous classes
        final char start = vmname.charAt(internalPosition);
        return !Character.isJavaIdentifierStart(start);
    }

    public static String getClassName(final String vmname, final String vmsignature,
                               final String vmsuperclass, final String[] vminterfaces) {
        if (isAnonymous(vmname)) {
            final String vmsupertype;
            if (vminterfaces != null && vminterfaces.length > 0) {
                vmsupertype = vminterfaces[0];
            } else if (vmsuperclass != null) {
                vmsupertype = vmsuperclass;
            } else {
                vmsupertype = null;
            }
            // append Eclipse style label, e.g. "Foo.new Bar() {...}"
            if (vmsupertype != null) {
                final StringBuilder builder = new StringBuilder();
                final String vmenclosing = vmname.substring(0,
                        vmname.lastIndexOf('$'));
                builder.append(getClassName(vmenclosing)).append(".new ")
                        .append(getClassName(vmsupertype)).append("() {...}");
                return builder.toString();
            }
        }
        return getClassName(vmname);
    }

    public static String getQualifiedClassName(final String vmname) {
        return vmname.replace('/', '.');
    }

//    public static String getMethodName(final String vmclassname,
//                                final String vmmethodname, final String vmdesc,
//                                final String vmsignature) {
//        return getMethodName(vmclassname, vmmethodname, vmdesc, false);
//    }
//
//    public static String getQualifiedMethodName(final String vmclassname,
//                                         final String vmmethodname, final String vmdesc,
//                                         final String vmsignature) {
//        return getQualifiedClassName(vmclassname) + "."
//                + getMethodName(vmclassname, vmmethodname, vmdesc, true);
//    }

    public static String getMethodSignatureName(final String vmclassname,
                                                final String vmmethodname, final String vmdesc) {

        return "<" + getQualifiedClassName(vmclassname) + ": "
                + getMethodName(vmclassname, vmmethodname, vmdesc, true) + ">";
    }

    private static String getTypeStringFromObject(String obj) {
        String ret = "";

        if (obj.endsWith("[]")) {
            ret += "[";
            obj = obj.substring(0, obj.length() - 2);
        }

        if (obj.startsWith("byte")) {
            ret += "B";
        } else if (obj.startsWith("char")) {
            ret += "C";
        } else if (obj.startsWith("double")) {
            ret += "D";
        } else if (obj.startsWith("float")) {
            ret += "F";
        } else if (obj.startsWith("int")) {
            ret += "I";
        } else if (obj.startsWith("long")) {
            ret += "J";
        } else if (obj.startsWith("short")) {
            ret += "S";
        } else if (obj.startsWith("void")) {
            ret += "V";
        } else if (obj.startsWith("boolean")) {
            ret += "Z";
        } else if (obj.length() > 0) {
            ret += "L" + obj.replace('.', '/') + ";";
        }

        return ret;
    }

    public static String getKeyFromMethod(String methodSignature) {
        String [] lines = methodSignature.split(" ");
        if (lines.length < 3)
            return null;

        String ret = "";
        // class name
        ret += lines[0].substring(1).replace('.', '/') + " ";

        String [] methodLines = lines[2].substring(0, lines[2].length() - 2).split("\\(");

        // method name
        ret += methodLines[0];
        ret += "(";
        if (methodLines.length > 1) {
            for (String argLine : methodLines[1].split(",")) {
                ret += getTypeStringFromObject(argLine);
            }
        }
        ret += ")";

        ret += getTypeStringFromObject(lines[1]);

        return ret;
    }

    public static String getKeyFromMethod(final String vmclassname,
                                          final String vmmethodname, final String vmdesc) {

        return vmclassname + ": " + vmmethodname + vmdesc;
    }

    private static String getMethodName(final String vmclassname,
                                 final String vmmethodname, final String vmdesc,
                                 final boolean qualifiedParams) {
        if ("<clinit>".equals(vmmethodname)) {
//            return "static {...}";
            return "<clinit>()";
        }
        final StringBuilder result = new StringBuilder();
        if ("<init>".equals(vmmethodname)) {
            if (isAnonymous(vmclassname)) {
//                return "{...}";
                result.append("<init>");
            } else {
//                result.append(getClassName(vmclassname));
                result.append("<init>");
            }
        } else {
            result.append(vmmethodname);
        }
        result.append('(');
        final Type[] arguments = Type.getArgumentTypes(vmdesc);
        boolean comma = false;
        for (final Type arg : arguments) {
            if (comma) {
                result.append(",");
            } else {
                comma = true;
            }
            if (qualifiedParams) {
                result.append(getQualifiedClassName(arg.getClassName()));
            } else {
                result.append(getShortTypeName(arg));
            }
        }
        result.append(')');
        return result.toString();
    }

    private static String getShortTypeName(final Type type) {
        final String name = type.getClassName();
        final int pos = name.lastIndexOf('.');
        final String shortName = pos == -1 ? name : name.substring(pos + 1);
        return shortName.replace('$', '.');
    }
}
