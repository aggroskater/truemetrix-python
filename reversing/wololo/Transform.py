#!/usr/bin/env python3

# truemetrix
# Copyright (C) 2021 Preston Maness
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from attrs import define, Factory
from abc import ABC, abstractmethod

@define
class Transform(ABC, Generic[I,O]):
    # could probably use inp and out to validate pipelines prior
    # to executing them. I.e., parent.out == child.inp for all
    # parent-child relationships.
    _inp : I = any
    _out : O = any
    #nxt: None | Transform(Generic[O,any]) = None
    #metadata: dict = Factory(dict)
    path: List[str]
    #def invoke(self): return self.transform
    @abstractmethod
    def transform(input: I) -> O: pass


# Examples...

# Do I need `inp` and `out`? What about `nxt` and `invoke`?
# I'm trying to mimic what I've seen in OWIN middleware in
# the C#/ASP.NET world.

class TransformStringToInt(Transform[str,int]):
    def transform(input: str) -> int:
        return int(input)

class TransformIntToFourByteBigSigned(Transform[int,bytes]):
    def transform(input: int) -> bytes:
        return input.to_bytes(4, byteorder='big', signed=True)

class TransformIntToFourByteBigUnsigned(Transform[int,bytes]):
    def transform(input: int) -> bytes:
        return input.to_bytes(4, byteorder='big', signed=False)

class TransformIntToFourByteLittleSigned(Transform[int,bytes]):
    def transform(input: int) -> bytes:
        return input.to_bytes(4, byteorder='little', signed=True)

class TransformIntToFourByteLittleUnsigned(Transform[int,bytes]):
    def transform(input: int) -> bytes:
        return input.to_bytes(4, byteorder='little', signed=False)

##############

# What seems to be the "usual" approach...

comparables = []
pipelines = [
    [TransformStringToInt,TransformIntToFourByteBigSigned],
    [TransformStringToInt,TransformIntToFourByteBigUnsigned]
]

pipelines2 = [
    [TransformStringToInt,[Transform1,Transform2,Transform3,Transform4],[Transform5,Transform6]]
]
comparables2 = []

for row in csv:
    data = row[0]
    for pipeline in pipelines:
        path = []
        for transform in pipeline:
            path.append(transform.__name__)
            transform.path = path
            data = transform.transform(data)
        comparables.append(data)

    for pipeline in pipelines2:
        path = []
        for transform in pipeline:
            if transform is list:
                # NOPE IT DON'T WORK -__-
                for internal in transform:
                    path.append(transform.__name__)
                    transform.path = path
                    data = transform.transform(data)
            else:
                path.append(transform.__name__)
                transform.path = path
                data = transform.transform(data)
        comparables.append(data)

# HMMMM. Thinking I might want to use anytree:
#
# https://stackoverflow.com/questions/2358045/how-can-i-implement-a-tree-in-python

# What I actually want...

    comparable = TransformStringToInt(row[0])
      .TransformIntToByteBigSigned()
      .TransformToComparable()

# Basically, I want the knowledge of the pipeline's structure to
# be baked into its construction. And I don't want to be limited
# to just one step after the other. Ideally, I'd have an ability
# to descend through trees of transforms:
#
# TransformA
# |
# |->TransformB
# |
# |->TransformC->TransformG->TransformH
# |
# |->TransformD
#    |
#    |->TransformE->TransformI
#    |->TransformF
#
# And what I'd end up with four different traversals of the tree,
# and four comparables.
#
#
# I'd also like to do this with generators so that we can handle
# larger inputs. Maybe even link the transform output up to the
# various comparison operations and make that memory-constrained
# too.

#
# Hmm... But if we want a tree structure, you could see the same
# transform in multiple spots of the tree. In that case, you
# probably wouldn't want a fluent approach. Or at least, the
# transforms themselves and their arrangement are separate concerns,
# so perhaps don't force the arrangement to be associated with
# the transform?
#
