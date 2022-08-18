package com.maliciousemaildetector.util;

import weka.classifiers.meta.FilteredClassifier;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;
import weka.experiment.InstanceQuery;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.NominalToString;
import java.sql.SQLException;
import java.util.ArrayList;

public class WekaPredictionUtil {

    public static double getPrediction(String emailText) throws Exception {
        InstanceQuery query1 = new InstanceQuery();
        query1.setUsername("postgres");
        query1.setPassword("p@ssw0rd");
        query1.setQuery("SELECT * FROM spamdataset LIMIT 6000");
        Instances trainDataSet1 = query1.retrieveInstances();
        NominalToString convert = new NominalToString();
        String[] options = new String[2];
        options[0] = "-C";
        options[1] = "first";  //range of variables to make numeric
        convert.setOptions(options);
        convert.setInputFormat(trainDataSet1);
        Instances trainDataSet = Filter.useFilter(trainDataSet1, convert);
        trainDataSet.setClassIndex(trainDataSet.numAttributes() - 1);
        Instances testDataSet = createNewInstance(emailText);
        testDataSet.setClassIndex(testDataSet.numAttributes() - 1);

        FilteredClassifier filteredClassifier = new FilteredClassifier();
        filteredClassifier.setOptions(weka.core.Utils.splitOptions("-F \"weka.filters.unsupervised.attribute.StringToWordVector -R first-last -W 1000 -prune-rate -1.0 -N 0 -stemmer weka.core.stemmers.NullStemmer -stopwords-handler weka.core.stopwords.Null -M 1 -tokenizer \\\"weka.core.tokenizers.WordTokenizer -delimiters \\\\\\\" \\\\\\\\r\\\\\\\\n\\\\\\\\t.,;:\\\\\\\\\\\\\\'\\\\\\\\\\\\\\\"()?!\\\\\\\"\\\"\" -S 1 -W weka.classifiers.bayes.NaiveBayesMultinomial"));
        filteredClassifier.buildClassifier(trainDataSet);
        double pred = 0;
        for (int i = 0; i < testDataSet.numInstances(); i++) {
            pred = filteredClassifier.classifyInstance(testDataSet.instance(i));
            System.out.print("ID: " + testDataSet.instance(i).value(0));
            System.out.print(", actual: " + testDataSet.classAttribute().value((int) testDataSet.instance(i).classValue()));
            // double pref1 = svm1.classifyInstance(testData.instance(i));
            System.out.println(", predicted : " + (int) pred);
        }
        return pred;
    }

    public static Instances createNewInstance(String emailBodyContent) {
        ArrayList<Attribute> attributes = new ArrayList<Attribute>(2);
        ArrayList<String> classVal = new ArrayList<String>();
        classVal.add("1");
        classVal.add("0");
        attributes.add(new Attribute("Text", (ArrayList<String>) null));
        attributes.add(new Attribute("class-att", classVal));
        Instances dataRaw = new Instances("spamEmailDetection", attributes, 0);
        if (dataRaw.size() >= 0) {
            dataRaw.clear();
            double[] instanceValue1 = new double[dataRaw.numAttributes()];
            instanceValue1[0] = dataRaw.attribute(0).addStringValue(emailBodyContent);
            instanceValue1[1] = 0;
            dataRaw.add(new DenseInstance(1.0, instanceValue1));
        }
        return dataRaw;
    }

    public static void main(String[] args) throws ClassNotFoundException,
            SQLException, Exception {

        /***************************
         * Instances from Database
         ****************************/
        InstanceQuery query1 = new InstanceQuery();

        query1.setUsername("postgres");
        query1.setPassword("p@ssw0rd");
        query1.setQuery("SELECT * FROM spamdataset LIMIT 6000");
        Instances trainDataSet1 = query1.retrieveInstances();

        NominalToString convert = new NominalToString();
        String[] options = new String[2];
        options[0] = "-C";
        options[1] = "first";  //range of variables to make numeric
        convert.setOptions(options);
        convert.setInputFormat(trainDataSet1);
        Instances trainDataSet = Filter.useFilter(trainDataSet1, convert);
        trainDataSet.setClassIndex(trainDataSet.numAttributes() - 1);
        /**
         * Loading test data set
         */
        String emailText = "What class of  &lt;#&gt;  reunion?";
        Instances testDataSet = createNewInstance(emailText);
        testDataSet.setClassIndex(testDataSet.numAttributes() - 1);

        FilteredClassifier fc = new FilteredClassifier();
        fc.setOptions(weka.core.Utils.splitOptions("-F \"weka.filters.unsupervised.attribute.StringToWordVector -R first-last -W 1000 -prune-rate -1.0 -N 0 -stemmer weka.core.stemmers.NullStemmer -stopwords-handler weka.core.stopwords.Null -M 1 -tokenizer \\\"weka.core.tokenizers.WordTokenizer -delimiters \\\\\\\" \\\\\\\\r\\\\\\\\n\\\\\\\\t.,;:\\\\\\\\\\\\\\'\\\\\\\\\\\\\\\"()?!\\\\\\\"\\\"\" -S 1 -W weka.classifiers.bayes.NaiveBayesMultinomial"));
        fc.buildClassifier(trainDataSet);

        // double[] prediction = fc.distributionForInstance(testDataSet);
        double pred;
        for (int i = 0; i < testDataSet.numInstances(); i++) {
            pred = fc.classifyInstance(testDataSet.instance(i));
            System.out.print("ID: " + testDataSet.instance(i).value(0));
            System.out.print(", actual: " + testDataSet.classAttribute().value((int) testDataSet.instance(i).classValue()));
            // double pref1 = svm1.classifyInstance(testData.instance(i));
            System.out.println(", predicted : " + (int) pred);
        }

    }


    public static Instances createNewInstance23() {
        ArrayList<Attribute> atts = new ArrayList<Attribute>(2);
        ArrayList<String> classVal = new ArrayList<String>();
        classVal.add("1");
        classVal.add("0");
        atts.add(new Attribute("Text", (ArrayList<String>) null));
        atts.add(new Attribute("class-att", classVal));

        Instances dataRaw = new Instances("test", atts, 0);
        System.out.println("Before adding any instance");
        System.out.println("--------------------------");
        System.out.println(dataRaw);
        System.out.println("--------------------------");

        double[] instanceValue1 = new double[dataRaw.numAttributes()];

        instanceValue1[0] = dataRaw.attribute(0).addStringValue("What class of  &lt;#&gt;  reunion?");
        instanceValue1[1] = 0;

        dataRaw.add(new DenseInstance(1.0, instanceValue1));

        System.out.println("After adding a instance");
        System.out.println("--------------------------");
        System.out.println(dataRaw);
        System.out.println("--------------------------");

        double[] instanceValue2 = new double[dataRaw.numAttributes()];

        instanceValue2[0] = dataRaw.attribute(0).addStringValue("Are you free now?can i call now?");
        instanceValue2[1] = 1;

        dataRaw.add(new DenseInstance(1.0, instanceValue2));

        System.out.println("After adding second instance");
        System.out.println("--------------------------");
        System.out.println(dataRaw);
        System.out.println("--------------------------");

        return dataRaw;
    }
}



