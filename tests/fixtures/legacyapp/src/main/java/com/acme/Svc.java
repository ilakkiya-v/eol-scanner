package com.acme;
import java.io.*;
public class Svc {
  Object read(InputStream in) throws Exception { return new ObjectInputStream(in).readObject(); }
}
