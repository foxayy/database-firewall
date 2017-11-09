#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os
import sklearn.feature_extraction
import pandas as pd
# Use the SQLParse module: sqlparse is a non-validating SQL parser module for Python
import sqlparse
# The data hacking repository has a simple stats module we're going to use
import simple_stats as ss
import math
from collections import Counter
import numpy as np
import sklearn.ensemble
from sklearn.model_selection import train_test_split
from sklearn.externals import joblib

def transform_fit_save(dataframe, df_stats) :
    dataframe['length'] = dataframe['parsed_sql'].map(lambda x: len(x))
    dataframe['entropy'] = dataframe['raw_sql'].map(lambda x: entropy(x))
    dataframe['malicious_g'] = dataframe['sequences'].map(lambda x: g_aggregate(df_stats, x, 'malicious_g'))
    dataframe['legit_g'] = dataframe['sequences'].map(lambda x: g_aggregate(df_stats, x, 'legit_g'))
    X = dataframe.as_matrix(['length', 'entropy','legit_g','malicious_g'])
    # Labels (scikit learn uses 'y' for classification labels)
    y = np.array(dataframe['type'].tolist())
    clf = sklearn.ensemble.RandomForestClassifier(n_estimators=30) # Trees in the forest
    # Train on a 80/20 split
    X_train, X_test, y_train, y_test, index_train, index_test = train_test_split(X, y, dataframe.index, test_size=0.2)
    print 'Model fitting'
    clf.fit(X_train, y_train)
    joblib.dump(clf,"./model/train_model.m")
    print 'Model saved'

def load_dataframe_dfstats():
    # Read in a set of SQL statements from various sources
    basedir = './data'
    filelist = os.listdir(basedir) 
    df_list = []
    for file in filelist:
        df = pd.read_csv(os.path.join(basedir,file), sep='|||', names=['raw_sql'], header=None, engine='python')
        df['type'] = 'legit' if file.split('.')[0] == 'legit' else 'malicious'
        df_list.append(df)
    dataframe = pd.concat(df_list, ignore_index=True)
    dataframe.dropna(inplace=True)
    dataframe['parsed_sql'] = dataframe['raw_sql'].map(lambda x: parse_it(x))
    dataframe['sequences'] = dataframe['parsed_sql'].map(lambda x: ngrams(x, 3))
    # Spin up our g_test class
    g_test = ss.GTest()
    # Here we'd like to see how various sql tokens and transitions are related.
    # Is there an association with particular token sets and malicious SQL statements.
    tokens, types = token_expansion(dataframe['sequences'], dataframe['type'])
    df_ct, df_cd, df_stats = g_test.highest_gtest_scores(tokens, types, matches=0, N=0)
    return dataframe, df_stats

def parse_it(raw_sql):
    parsed = sqlparse.parse(unicode(raw_sql,'utf-8'))
    return [token._get_repr_name() for parse in parsed for token in parse.tokens if token._get_repr_name() != 'Whitespace']

def ngrams(lst, N):
    ngrams = []
    for n in xrange(0,N):
        ngrams += zip(*(lst[i:] for i in xrange(n+1)))
    return [str(tuple) for tuple in ngrams]

def token_expansion(series, types):
    _tokens, _types = zip(*[(token,token_type) for t_list,token_type in zip(series,types) for token in t_list])
    return pd.Series(_tokens), pd.Series(_types)

# Generating additional feature dimensions for the machine learning to expand its mind into...
# We're basically building up features to include into our 'feature vector' for ML
def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())


# For each SQL statement aggregate the malicious and legit g-test scores as features
def g_aggregate(df_stats, sequence, name):
    try:
        g_scores = [df_stats.ix[item][name] for item in sequence]
    except KeyError:
        return 0
    return sum(g_scores)/len(g_scores) if g_scores else 0 # Average

def load_predict(query, df_stats, clf):
    parsed_sql = parse_it(query)
    ngram_list = ngrams(parsed_sql, 3)
    malicious_g = g_aggregate(df_stats, ngram_list, 'malicious_g')
    legit_g = g_aggregate(df_stats, ngram_list, 'legit_g')
    _X = np.array([len(parsed_sql), entropy(query), legit_g, malicious_g])
    _X = _X.reshape(1,-1)
    return clf.predict(_X)[0]

