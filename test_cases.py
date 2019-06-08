import torch
import pdb

def approx_equals(a,b):
    return abs(a - b) < 1e-5

def test_evaluation_function(evaluation_function):

    test_result = True

    predictions = [0, 0, 0, 0]
    ground_truth = [1, 1, 0, 0]
    precision, recall, f_score, classification_accuracy = evaluation_function(predictions, ground_truth)

    test_result = test_result and approx_equals(precision, 0.5)
    test_result = test_result and approx_equals(recall, 1.0)
    test_result = test_result and approx_equals(f_score, 2.0/3.0)
    test_result = test_result and approx_equals(classification_accuracy, 0.5)

    predictions = [1, 1, 0, 0]
    ground_truth = [1, 1, 0, 0]
    precision, recall, f_score, classification_accuracy = evaluation_function(predictions, ground_truth)

    test_result = test_result and approx_equals(precision, 1.0)
    test_result = test_result and approx_equals(recall, 1.0)
    test_result = test_result and approx_equals(f_score, 1.0)
    test_result = test_result and approx_equals(classification_accuracy, 1.0)

    return test_result

def test_split_dataset(split_dataset_function, vuln, clean):
    dataset, train_set, val_set, test_set = split_dataset_function(vuln, clean)

    #check the number of examples in the dataset equals number in vuln + clean
    length_equal = (len(dataset) == len(vuln) + len(clean))

    #check there are no overlaps between the train, val, and test set indexes
    dataset_counter = torch.zeros(len(dataset))
    for i in range(len(train_set[0])):
        idx = train_set[0][i]
        dataset_counter[idx] += 1
    for i in range(len(val_set[0])):
        idx = val_set[0][i]
        dataset_counter[idx] += 1
    for i in range(len(test_set[0])):
        idx = test_set[0][i]
        dataset_counter[idx] += 1

    no_overlaps = torch.sum(dataset_counter).item() == len(dataset)

    #check the list of labels are equal length to the list of indexes
    set_length = (len(train_set[0]) == len(train_set[1])) and (len(val_set[0]) == len(val_set[1])) and (len(test_set[0]) == len(test_set[1]))

    #pdb.set_trace()

    #check the list of '1' labels equals the number of clean samples
    num_ones = torch.DoubleTensor(train_set[1]).sum() + torch.DoubleTensor(val_set[1]).sum() + torch.DoubleTensor(test_set[1]).sum()
    check_number_ones = (num_ones.item() == len(clean))

    #check that all values in the dataset_counter are 1
    check_bounds = approx_equals(torch.max(dataset_counter).item(),1) and approx_equals(torch.min(dataset_counter).item(),1)

    return length_equal and check_number_ones and check_bounds and no_overlaps

def test_network(MalwareDetectorNetwork):
    
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    net = MalwareDetectorNetwork()
    net.to(device)

    test_input = torch.randperm(217)
    test_input = test_input.unsqueeze(0)
    test_input = torch.LongTensor(test_input)

    test_input = test_input.to(device)
    output = net(test_input)
    output_size = output.size()
    test_result = (output_size[0] == 1 and output_size[1] == 2)
    return test_result
